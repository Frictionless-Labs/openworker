// Spreadsheet parse adapter (OWH M02 / OW-SEC-002).
//
// Workbook bytes are hostile input: they arrive as an artifact the agent produced from a
// download, an email attachment, or a path inside a granted root, and the preview parses
// them inside the PRIVILEGED app webview. The parser is therefore kept behind this one
// narrow interface so it can be replaced without touching artifact routing, and so every
// safety property below is enforced in one place rather than at each call site.
//
// Why not SheetJS: npm's `xlsx` is frozen at 0.18.5, which carries GHSA-4r6h-8v6p-xvw6
// (prototype pollution) and GHSA-5pgg-2g8v-p4x9 (ReDoS). The fixed >=0.20.2 build is
// published only from cdn.sheetjs.com, which cannot be pinned through the npm lockfile the
// release gate verifies with `npm ci`. `read-excel-file` is maintained, MIT, on the
// registry, and covers the OOXML path the preview actually needs.
//
// Deliberately NOT supported: legacy `.xls` (OLE2 compound binary). That format needs a
// second, far larger binary parser for a file the UI already tells the user is "best viewed
// in a real app". Refusing it removes the attack surface instead of hardening it.

export type SheetTable = { name: string; rows: unknown[][] };

export type ParseLimits = {
  maxBytes: number;
  maxSheets: number;
  maxRows: number;
  maxCols: number;
  timeoutMs: number;
};

// Bounds, not preferences: each one is a documented failure mode of the previous parser.
export const DEFAULT_LIMITS: ParseLimits = {
  maxBytes: 25 * 1024 * 1024,
  maxSheets: 32,
  maxRows: 5000,
  maxCols: 256,
  timeoutMs: 10_000,
};

export type ParseFailure =
  | "empty"
  | "too_large"
  | "legacy_xls_unsupported"
  | "unsupported_format"
  | "timeout"
  | "parse_failed";

export class SheetParseError extends Error {
  readonly code: ParseFailure;
  constructor(code: ParseFailure, message: string) {
    super(message);
    this.name = "SheetParseError";
    this.code = code;
  }
}

// OOXML is a ZIP: "PK\x03\x04" (or the empty/spanned variants). Legacy .xls is the OLE2
// compound-file header. Sniffing bytes rather than trusting the extension means a renamed
// file cannot steer the preview into a parser it was never meant to reach.
const ZIP_MAGIC = [0x50, 0x4b];
const OLE2_MAGIC = [0xd0, 0xcf, 0x11, 0xe0];

function startsWith(bytes: Uint8Array, magic: number[]): boolean {
  if (bytes.length < magic.length) return false;
  return magic.every((b, i) => bytes[i] === b);
}

/** Decode a `data:` URL's base64 payload. Throws SheetParseError rather than a raw DOMException. */
export function decodeDataUrl(dataUrl: string): Uint8Array {
  const base64 = (dataUrl || "").split(",")[1] || "";
  if (!base64) throw new SheetParseError("empty", "no workbook data");
  let binary: string;
  try {
    binary = atob(base64);
  } catch {
    throw new SheetParseError("unsupported_format", "workbook data is not valid base64");
  }
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// Cells are rendered as text and never used as object keys, so a workbook carrying
// "__proto__" or "constructor" in a cell or a sheet name can reach the DOM as a STRING and
// nothing else. This function is the only thing that decides what a cell becomes.
function cellText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (value instanceof Date) return value.toISOString();
  if (typeof value === "object") return "";
  return String(value);
}

/**
 * Bound a parse so a pathological workbook cannot hang the webview (the GHSA-5pgg-2g8v-p4x9
 * ReDoS class). Exported so the bound itself is testable: the parser is fast on every input
 * a test can cheaply construct, so proving the guard through `parseWorkbook` would only ever
 * prove that the guard did not fire.
 */
export function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const guard = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new SheetParseError("timeout", `workbook parse exceeded ${ms}ms`)),
      ms,
    );
  });
  return Promise.race([work, guard]).finally(() => clearTimeout(timer)) as Promise<T>;
}

/**
 * Parse workbook bytes into plain row arrays, or throw `SheetParseError`.
 *
 * Every returned value is a string built by `cellText`; no parsed value is ever used as a
 * property name, so a hostile workbook cannot reach `Object.prototype`.
 */
export async function parseWorkbook(
  bytes: Uint8Array,
  limits: Partial<ParseLimits> = {},
): Promise<SheetTable[]> {
  const lim: ParseLimits = { ...DEFAULT_LIMITS, ...limits };

  if (!bytes || bytes.length === 0) {
    throw new SheetParseError("empty", "workbook is empty");
  }
  if (bytes.length > lim.maxBytes) {
    throw new SheetParseError(
      "too_large",
      `workbook is ${bytes.length} bytes, over the ${lim.maxBytes}-byte preview limit`,
    );
  }
  if (startsWith(bytes, OLE2_MAGIC)) {
    throw new SheetParseError(
      "legacy_xls_unsupported",
      "legacy .xls workbooks are not previewed — open this file in a spreadsheet app",
    );
  }
  if (!startsWith(bytes, ZIP_MAGIC)) {
    throw new SheetParseError("unsupported_format", "not an .xlsx (OOXML) workbook");
  }

  // Copied into its own buffer: `bytes` may be a view onto a larger ArrayBuffer, and the
  // parser would otherwise see the whole thing.
  const buffer = bytes.slice().buffer as ArrayBuffer;

  return withTimeout(
    (async () => {
      // Browser entry: the preview runs in the webview, and this build takes an
      // ArrayBuffer directly rather than reaching for Node streams.
      const readXlsxFile = (await import("read-excel-file/browser")).default;
      let sheets: { sheet: string; data: unknown[][] }[];
      try {
        // v9's default export returns every sheet as `{ sheet, data }`.
        sheets = (await readXlsxFile(buffer)) as unknown as {
          sheet: string;
          data: unknown[][];
        }[];
      } catch (e) {
        throw new SheetParseError("parse_failed", describe(e));
      }
      if (!Array.isArray(sheets)) {
        throw new SheetParseError("parse_failed", "workbook contained no readable sheets");
      }
      return sheets.slice(0, lim.maxSheets).map((sheet) => ({
        name: cellText(sheet?.sheet),
        rows: (Array.isArray(sheet?.data) ? sheet.data : [])
          .slice(0, lim.maxRows)
          .map((row) => (Array.isArray(row) ? row.slice(0, lim.maxCols).map(cellText) : [])),
      }));
    })(),
    lim.timeoutMs,
  );
}

function describe(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

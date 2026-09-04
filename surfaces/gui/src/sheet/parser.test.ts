// Hostile-workbook corpus for the spreadsheet parse adapter (OWH M02 / OW-SEC-002).
//
// Two halves, per the OWH development principle: the malicious case must fail SAFELY, and
// the legitimate case must still work. A corpus that only proves refusals would pass just
// as well with the preview deleted.

import { describe, expect, it } from "vitest";
import {
  DEFAULT_LIMITS,
  SheetParseError,
  decodeDataUrl,
  parseWorkbook,
  withTimeout,
} from "./parser";
import { makeLegacyXls, makeXlsx, makeZip } from "./testWorkbook";

async function failureCode(bytes: Uint8Array, limits = {}): Promise<string> {
  try {
    await parseWorkbook(bytes, limits);
  } catch (e) {
    expect(e).toBeInstanceOf(SheetParseError);
    return (e as SheetParseError).code;
  }
  throw new Error("expected parseWorkbook to reject");
}

describe("benign workbooks still work", () => {
  it("reads rows and columns from a single sheet", async () => {
    const bytes = makeXlsx([
      { name: "Revenue", rows: [["month", "mrr"], ["Aug", "6000"]] },
    ]);
    const tables = await parseWorkbook(bytes);
    expect(tables).toHaveLength(1);
    expect(tables[0].name).toBe("Revenue");
    expect(tables[0].rows[0]).toEqual(["month", "mrr"]);
    expect(tables[0].rows[1]).toEqual(["Aug", "6000"]);
  });

  it("reads every sheet in a multi-sheet workbook", async () => {
    const bytes = makeXlsx([
      { name: "One", rows: [["a"]] },
      { name: "Two", rows: [["b"]] },
    ]);
    const tables = await parseWorkbook(bytes);
    expect(tables.map((t) => t.name)).toEqual(["One", "Two"]);
    expect(tables[1].rows[0]).toEqual(["b"]);
  });
});

describe("prototype pollution (GHSA-4r6h-8v6p-xvw6 class)", () => {
  it("a workbook whose cells and sheet name are __proto__ keys pollutes nothing", async () => {
    const bytes = makeXlsx([
      {
        name: "__proto__",
        rows: [
          ["__proto__", "constructor"],
          ["polluted", "yes"],
          ["prototype", "toString"],
        ],
      },
    ]);
    const tables = await parseWorkbook(bytes);

    // The hostile strings survive as DATA…
    expect(tables[0].rows[0]).toEqual(["__proto__", "constructor"]);
    // …and nothing reached Object.prototype.
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(({} as Record<string, unknown>).yes).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, "polluted")).toBe(false);
    expect([].constructor).toBe(Array);
  });

  it("never returns a non-primitive cell that could carry a payload", async () => {
    const bytes = makeXlsx([{ name: "S", rows: [["x", "y"]] }]);
    const tables = await parseWorkbook(bytes);
    for (const row of tables[0].rows) {
      for (const cell of row) expect(typeof cell).toBe("string");
    }
  });
});

describe("malformed and hostile containers fail closed", () => {
  it("rejects empty input", async () => {
    expect(await failureCode(new Uint8Array(0))).toBe("empty");
  });

  it("rejects non-OOXML bytes rather than guessing a parser", async () => {
    expect(await failureCode(new TextEncoder().encode("not a workbook at all"))).toBe(
      "unsupported_format",
    );
  });

  it("refuses legacy .xls instead of reaching for a binary parser", async () => {
    expect(await failureCode(makeLegacyXls())).toBe("legacy_xls_unsupported");
  });

  it("rejects a workbook over the size limit before parsing it", async () => {
    const big = new Uint8Array(2048);
    big[0] = 0x50;
    big[1] = 0x4b;
    expect(await failureCode(big, { maxBytes: 1024 })).toBe("too_large");
  });

  it("a truncated ZIP fails as a parse error, not a hang or a crash", async () => {
    const whole = makeXlsx([{ name: "S", rows: [["a"]] }]);
    const truncated = whole.slice(0, Math.floor(whole.length / 2));
    const code = await failureCode(truncated);
    expect(["parse_failed", "unsupported_format", "timeout"]).toContain(code);
  });

  it("a ZIP with OOXML magic but no workbook part fails closed", async () => {
    expect(await failureCode(makeZip({ "junk.txt": "hello" }))).toBe("parse_failed");
  });

  it("bounds parse time so a ReDoS-shaped workbook cannot hang the UI (GHSA-5pgg-2g8v-p4x9 class)", async () => {
    // A parse that never settles is exactly what a ReDoS input produces. The guard must
    // reject it rather than leave the preview spinning forever.
    const neverSettles = new Promise<never>(() => {});
    await expect(withTimeout(neverSettles, 5)).rejects.toMatchObject({
      name: "SheetParseError",
      code: "timeout",
    });
  });

  it("the timeout guard does not fire on work that finishes inside the budget", async () => {
    await expect(withTimeout(Promise.resolve("done"), 5_000)).resolves.toBe("done");
  });
});

describe("output bounds", () => {
  it("caps rows and columns so a declared-huge sheet cannot exhaust the renderer", async () => {
    const rows = Array.from({ length: 40 }, (_, r) =>
      Array.from({ length: 40 }, (_, c) => `r${r}c${c}`),
    );
    const tables = await parseWorkbook(makeXlsx([{ name: "S", rows }]), {
      maxRows: 5,
      maxCols: 3,
    });
    expect(tables[0].rows).toHaveLength(5);
    expect(tables[0].rows[0]).toHaveLength(3);
  });

  it("caps the number of sheets", async () => {
    const sheets = Array.from({ length: 6 }, (_, i) => ({
      name: `S${i}`,
      rows: [["x"]],
    }));
    const tables = await parseWorkbook(makeXlsx(sheets), { maxSheets: 2 });
    expect(tables).toHaveLength(2);
  });

  it("ships bounded defaults", () => {
    expect(DEFAULT_LIMITS.maxBytes).toBeLessThanOrEqual(50 * 1024 * 1024);
    expect(DEFAULT_LIMITS.timeoutMs).toBeGreaterThan(0);
  });
});

describe("decodeDataUrl", () => {
  it("round-trips a base64 payload", () => {
    expect(Array.from(decodeDataUrl("data:application/octet-stream;base64,UEsD"))).toEqual([
      0x50, 0x4b, 0x03,
    ]);
  });

  it("rejects a data URL with no payload", () => {
    expect(() => decodeDataUrl("data:application/octet-stream;base64,")).toThrow(
      SheetParseError,
    );
  });
});

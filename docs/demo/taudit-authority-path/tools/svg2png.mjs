import { readFile, writeFile } from "node:fs/promises";
import { Resvg } from "@resvg/resvg-js";
const [,, inp, outp] = process.argv;
const svg = await readFile(inp, "utf8");
const r = new Resvg(svg, { fitTo: { mode: "width", value: 1600 }, background: "white" });
await writeFile(outp, r.render().asPng());
console.log("png:", outp);

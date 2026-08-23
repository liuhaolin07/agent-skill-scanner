import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import process from "node:process";

const port = Number(process.env.PORT || 4173);
const root = join(process.cwd(), "public");
const types = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" };

createServer(async (request, response) => {
  try {
    const requested = request.url === "/" ? "/index.html" : decodeURIComponent(request.url.split("?")[0]);
    const safePath = normalize(requested).replace(/^(?:\.\.[\\/])+/, "").replace(/^[\\/]+/, "").replace(/\\/g, "/");
    const filePath = safePath === "scanner.js" ? join(process.cwd(), "src", "scanner.js")
      : safePath === "rules/rules.js" ? join(process.cwd(), "rules", "rules.js")
      : join(root, safePath);
    const content = await readFile(filePath);
    response.writeHead(200, { "Content-Type": types[extname(filePath)] || "application/octet-stream", "X-Content-Type-Options": "nosniff" });
    response.end(content);
  } catch {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    response.end("Not found");
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`Agent Skill Scanner is running at http://127.0.0.1:${port}`);
});

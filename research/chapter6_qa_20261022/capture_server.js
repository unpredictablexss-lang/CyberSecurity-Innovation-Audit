const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const outputDir = path.resolve(__dirname, "..", "deliveries", "chapter6_20261022", "images");
const allowed = new Set(["reviewed-candidates.png", "review-evidence.png"]);

http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") {
    res.writeHead(204).end();
    return;
  }
  const name = decodeURIComponent((req.url || "").slice(1));
  if (req.method !== "POST" || !allowed.has(name)) {
    res.writeHead(404).end("not found");
    return;
  }
  const chunks = [];
  req.on("data", chunk => chunks.push(chunk));
  req.on("end", () => {
    try {
      const image = Buffer.from(Buffer.concat(chunks).toString("utf8"), "base64");
      if (image.length < 1024 || image.length > 10 * 1024 * 1024) throw new Error("invalid image size");
      fs.writeFileSync(path.join(outputDir, name), image);
      res.writeHead(200, { "Content-Type": "text/plain" }).end(String(image.length));
    } catch (error) {
      res.writeHead(400, { "Content-Type": "text/plain" }).end(error.message);
    }
  });
}).listen(18889, "127.0.0.1", () => console.log(`capture server ready: ${outputDir}`));

// npm install express body-parser
// node aes_cbc.js

const express = require("express");
const crypto = require("crypto");
const bodyParser = require("body-parser");

const app = express();
const PORT = 5000;

// 全局密钥和IV
const KEY = Buffer.from("32byteslongsecretkeyforaes256!aa"); // 32字节密钥
const IV = Buffer.from("16byteslongiv456"); // 16字节IV
const JSON_KEY = "data";

// 中间件处理 JSON 请求
app.use(bodyParser.json({ limit: "10mb" }));

// 加密函数
function encrypt(content) {
  const cipher = crypto.createCipheriv("aes-256-cbc", KEY, IV);
  const encrypted = Buffer.concat([cipher.update(content), cipher.final()]);
  return encrypted;
}

// 解密函数
function decrypt(content) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", KEY, IV);
  const decrypted = Buffer.concat([decipher.update(content), decipher.final()]);
  return decrypted;
}

// 获取加密数据
function getData(content) {
  const bodyJson = JSON.parse(content.toString());
  return Buffer.from(bodyJson[JSON_KEY], "base64");
}

// 将数据转换为 JSON 字符串格式
function toData(content) {
  const bodyJson = {};
  bodyJson[JSON_KEY] = content.toString("base64");
  return Buffer.from(JSON.stringify(bodyJson));
}

// 请求钩子：hookRequestToBurp
app.post("/hookRequestToBurp", (req, res) => {
  try {
    const encryptedData = getData(Buffer.from(req.body.contentBase64, "base64"));
    const data = decrypt(encryptedData);
    req.body.contentBase64 = data.toString("base64");
    res.json(req.body);
  } catch (err) {
    res.status(500).send({ error: "Decryption failed" });
  }
});

// 请求钩子：hookRequestToServer
app.post("/hookRequestToServer", (req, res) => {
  try {
    const data = Buffer.from(req.body.contentBase64, "base64");
    const encryptedData = encrypt(data);
    const body = toData(encryptedData);
    req.body.contentBase64 = body.toString("base64");
    res.json(req.body);
  } catch (err) {
    res.status(500).send({ error: "Encryption failed" });
  }
});

// 响应钩子：hookResponseToBurp
app.post("/hookResponseToBurp", (req, res) => {
  try {
    const encryptedData = getData(Buffer.from(req.body.contentBase64, "base64"));
    const data = decrypt(encryptedData);
    req.body.contentBase64 = data.toString("base64");
    res.json(req.body);
  } catch (err) {
    res.status(500).send({ error: "Decryption failed" });
  }
});

// 响应钩子：hookResponseToClient
app.post("/hookResponseToClient", (req, res) => {
  try {
    const data = Buffer.from(req.body.contentBase64, "base64");
    const encryptedData = encrypt(data);
    const body = toData(encryptedData);
    req.body.contentBase64 = body.toString("base64");
    res.json(req.body);
  } catch (err) {
    res.status(500).send({ error: "Encryption failed" });
  }
});

// 启动服务
app.listen(PORT, () => {
  console.log(`Server running at http://0.0.0.0:${PORT}`);
});

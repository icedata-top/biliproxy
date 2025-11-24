import express from "express";
import axios from "axios";
import crypto from "crypto";
import { randUA } from "@ahmedrangel/rand-user-agent";
import { HttpsProxyAgent } from "https-proxy-agent";
import { HttpProxyAgent } from "http-proxy-agent";
import { config } from "./config.js";

const app = express();
const PORT = config.server.port;

// HTTP Proxy configuration
const PROXY_ENABLED = config.proxy.enabled;
const PROXY_URL = config.proxy.url;
const httpAgent = PROXY_ENABLED && PROXY_URL ? new HttpProxyAgent(PROXY_URL) : undefined;
const httpsAgent = PROXY_ENABLED && PROXY_URL ? new HttpsProxyAgent(PROXY_URL) : undefined;

// In-memory cache for WBI keys (you could use Redis in production)
const cache = {
  wbiKeys: null,
  wbiKeysExpiry: 0,
};

// Mixing key encoding table for WBI signature
const MIXIN_KEY_ENC_TAB = [
  46, 47, 18, 2, 53, 8, 23, 32, 15, 50, 10, 31, 58, 3, 45, 35, 27, 43, 5, 49,
  33, 9, 42, 19, 29, 28, 14, 39, 12, 38, 41, 13, 37, 48, 7, 16, 24, 55, 40, 61,
  26, 17, 0, 1, 60, 51, 30, 4, 22, 25, 54, 21, 56, 59, 6, 63, 57, 62, 11, 36,
  20, 34, 44, 52,
];

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS middleware
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept, Authorization"
  );

  if (req.method === "OPTIONS") {
    res.sendStatus(200);
  } else {
    next();
  }
});

// Security middleware - block scanner requests
app.use((req, res, next) => {
  const path = req.path.toLowerCase();
  const blockedPatterns = [
    /^\./, // Files starting with . (like .git, .env, .htaccess)
    /\.(git|svn|hg)/, // Version control directories
    /\.(env|config|conf)$/, // Config files
    /\.(log|txt|bak)$/, // Log and backup files
    /\.(sql|db|sqlite)$/, // Database files
    /\.(zip|tar|gz|rar)$/, // Archive files
    /\/(admin|wp-admin|wp-)/, // Admin panels
    /\/(vendor|node_modules|\.)/, // Package directories
    /\/(backup|backups)/, // Backup directories
    /\/(test|tests)/, // Test directories
    /\/\.well-known/, // Well-known directory (except for legitimate use)
    /\.(php|jsp|asp|py)$/, // Non-JS server files
    /\/robots\.txt$/, // Robots.txt
    /\/sitemap/, // Sitemaps
    /favicon\.ico$/, // Favicon
  ];

  const isBlocked = blockedPatterns.some((pattern) => pattern.test(path));

  if (isBlocked) {
    console.log(
      `🚫 Blocked scanner request: ${req.method} ${req.path} from ${req.ip}`
    );
    return res.status(404).json({ error: "Not found" });
  }

  next();
});

/**
 * Get mixin key by scrambling img_key and sub_key
 */
function getMixinKey(orig) {
  return MIXIN_KEY_ENC_TAB.map((n) => orig[n])
    .join("")
    .slice(0, 32);
}

/**
 * Fetch WBI keys from Bilibili API
 */
async function fetchWbiKeys() {
  try {
    const url = "https://api.bilibili.com/x/web-interface/nav";
    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    };

    const axiosConfig = {
      headers,
      timeout: config.proxy.timeout,
    };

    // Only add proxy agents if proxy is enabled
    if (httpAgent) axiosConfig.httpAgent = httpAgent;
    if (httpsAgent) axiosConfig.httpsAgent = httpsAgent;

    const response = await axios.get(url, axiosConfig);

    if (response.data?.data?.wbi_img) {
      const imgUrl = response.data.data.wbi_img.img_url;
      const subUrl = response.data.data.wbi_img.sub_url;

      const imgKey = imgUrl.substring(
        imgUrl.lastIndexOf("/") + 1,
        imgUrl.lastIndexOf(".")
      );
      const subKey = subUrl.substring(
        subUrl.lastIndexOf("/") + 1,
        subUrl.lastIndexOf(".")
      );

      // Keys are valid for 8 hours
      const expiresAt =
        Math.floor(Date.now() / 1000) + config.cache.wbiKeysExpiry;

      // Store in memory cache
      cache.wbiKeys = { imgKey, subKey };
      cache.wbiKeysExpiry = expiresAt;

      console.log("WBI keys fetched successfully, valid for 8 hours");
      console.log(
        `Response code: ${response.data?.code}, message: ${response.data?.message}`
      );
      console.log(`imgKey: ${imgKey}, subKey: ${subKey}`);
      return { imgKey, subKey };
    } else {
      console.error("Invalid response when fetching WBI keys", response.data);
      throw new Error("Failed to fetch WBI keys");
    }
  } catch (error) {
    console.error("Error fetching WBI keys:", error);
    throw error;
  }
}

/**
 * Get WBI keys, from cache or fetch new ones
 */
async function getWbiKeys() {
  const currentTime = Math.floor(Date.now() / 1000);

  if (cache.wbiKeys && currentTime < cache.wbiKeysExpiry) {
    return cache.wbiKeys;
  }

  // Fetch new keys
  return await fetchWbiKeys();
}

/**
 * Sign parameters with WBI signature
 */
async function signWithWbi(params) {
  const { imgKey, subKey } = await getWbiKeys();
  const mixinKey = getMixinKey(imgKey + subKey);

  // Add timestamp
  const wts = Math.floor(Date.now() / 1000);
  const paramsWithWts = { ...params, wts };

  // Sort and filter parameters
  const sortedParams = Object.keys(paramsWithWts)
    .sort()
    .reduce((acc, key) => {
      // Filter out special characters from values
      const value = String(paramsWithWts[key]).replace(/[!'()*]/g, "");
      acc[key] = value;
      return acc;
    }, {});

  // Build query string
  const query = Object.entries(sortedParams)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
    )
    .join("&");

  // Calculate MD5 hash for w_rid
  const w_rid = crypto
    .createHash("md5")
    .update(query + mixinKey)
    .digest("hex");

  // console.log(`Signing with mixin key: ${mixinKey}`);
  // console.log(`Query string: ${query}`);
  // console.log(`Generated w_rid: ${w_rid}`);

  return { ...params, w_rid, wts };
}

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    proxy: PROXY_ENABLED ? (PROXY_URL.replace(/\/\/.*@/, "//***:***@")) : "disabled",
  });
});

// WBI keys debug endpoint
app.get("/debug/wbi-keys", async (req, res) => {
  try {
    const keys = await getWbiKeys();
    res.json({
      ...keys,
      expiresAt: cache.wbiKeysExpiry,
      expiresIn: cache.wbiKeysExpiry - Math.floor(Date.now() / 1000),
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Robots.txt to discourage scanners
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow: /\n");
});

app.all("*", async (req, res) => {
  try {
    // Block root path access - disallow access to "/"
    if (req.path === "/") {
      console.log(`🚫 Blocked root access from ${req.ip}`);
      return res.status(404).json({ error: "Not found" });
    }

    const startTime = Date.now();
    let targetUrl = `https://api.bilibili.com${req.path}`;

    // For GET requests, sign the parameters
    if (req.method === "GET") {
      const signedParams = await signWithWbi(req.query);

      const queryString = Object.entries(signedParams)
        .map(
          ([key, value]) =>
            `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
        )
        .join("&");

      if (queryString) {
        targetUrl += `?${queryString}`;
      }
    }
    const userAgent = randUA();

    let headers = {
      ...req.headers,
      "User-Agent": userAgent, // This will override any existing User-Agent
      Referer: "https://www.bilibili.com/",
    };

    // Remove problematic headers that could reveal proxy infrastructure
    delete headers.host;
    delete headers["content-length"];
    delete headers["x-forwarded-for"];
    delete headers["x-forwarded-host"];
    delete headers["x-forwarded-proto"];
    delete headers["via"];
    delete headers["x-real-ip"];
    delete headers["cf-connecting-ip"];
    delete headers["cf-ipcountry"];
    delete headers["cf-ray"];
    delete headers["cf-visitor"];

    const axiosConfig = {
      method: req.method,
      url: targetUrl,
      headers,
      data: req.body,
      timeout: config.proxy.timeout,
      validateStatus: () => true,
    };

    // Only add proxy agents if proxy is enabled
    if (httpAgent) axiosConfig.httpAgent = httpAgent;
    if (httpsAgent) axiosConfig.httpsAgent = httpsAgent;

    const response = await axios(axiosConfig);

    const endTime = Date.now();
    const timePassed = endTime - startTime;

    // Log status and time for all requests
    console.log(`${response.status} - ${timePassed}ms`);

    // Only log detailed info for non-200 responses
    if (response.status !== 200) {
      console.log(`❌ Non-200 response details:`);
      console.log(`  Method: ${req.method}`);
      console.log(`  Original URL: ${req.originalUrl}`);
      console.log(`  Target URL: ${targetUrl}`);
      console.log(`  Status: ${response.status}`);
      console.log(`  Time: ${timePassed}ms`);
      console.log(`  Signed params:`, req.query);
      console.log(`  User-Agent: ${userAgent}`);
      console.log(`  Response data:`, response.data);
    }

    // Set response headers
    Object.entries(response.headers).forEach(([key, value]) => {
      if (
        !["connection", "transfer-encoding", "content-encoding"].includes(
          key.toLowerCase()
        )
      ) {
        res.set(key, value);
      }
    });

    // Add CORS headers
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization"
    );

    res.status(response.status).send(response.data);
  } catch (error) {
    console.error("Bilibili proxy error:", error);
    res.status(500).json({
      error: "Proxy request failed",
      message: error.message,
      url: error.config?.url,
    });
  }
});

app.listen(PORT, () => {
  console.log(`Bilibili API reverse proxy server running on port ${PORT}`);
  if (PROXY_ENABLED && PROXY_URL) {
    console.log(
      `Using HTTP proxy: ${PROXY_URL.replace(/\/\/.*@/, "//***:***@")}`
    );
  } else {
    console.log(`Proxy: disabled - direct connection`);
  }
  console.log("\nEndpoints:");
  console.log(`  Health check: http://localhost:${PORT}/health`);
  console.log(`  WBI keys debug: http://localhost:${PORT}/debug/wbi-keys`);
  console.log(`  Bilibili API: http://localhost:${PORT}/x/web-interface/nav`);
});

import express from "express";
import axios from "axios";
import crypto from "crypto";
import UserAgent from "user-agents";
import { HttpsProxyAgent } from "https-proxy-agent";
import { HttpProxyAgent } from "http-proxy-agent";
import { config } from "./config.js";
import { register, httpRequestDurationMs, httpResponseBytesTotal } from "./metrics.js";

const app = express();
const PORT = config.server.port;

// HTTP Proxy configuration
const PROXY_ENABLED = config.proxy.enabled;
const PROXY_URL = config.proxy.url;
const httpAgent = PROXY_ENABLED && PROXY_URL ? new HttpProxyAgent(PROXY_URL) : undefined;
const httpsAgent = PROXY_ENABLED && PROXY_URL ? new HttpsProxyAgent(PROXY_URL) : undefined;

// Initialize UserAgent generator for Windows Desktop
const userAgentGenerator = new UserAgent({ deviceCategory: 'desktop', platform: 'Win32' });

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

// Metrics middleware
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    // Normalize route for metrics to avoid high cardinality
    let route = req.path;
    if (route.startsWith('/cover/')) {
      route = '/cover';
    }
    httpRequestDurationMs
      .labels(req.method, route, res.statusCode)
      .observe(duration);

    // Record response size
    const contentLength = res.get('Content-Length');
    if (contentLength) {
      httpResponseBytesTotal
        .labels(req.method, route, res.statusCode)
        .inc(parseInt(contentLength));
    }
  });
  next();
});

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
    let headers = {
      "User-Agent": userAgentGenerator().toString(),
    };
    const sessdata = config.bilibili.sessdata;
    if (sessdata) {
      headers.cookie = `SESSDATA=${sessdata}`;
    }

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

// Metrics endpoint
app.get("/metrics", async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
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

/**
 * Axios wrapper with auto-retry logic
 * Retries on non-200 status codes, max 5 times, no wait
 * But if 404, pass through immediately
 * Regenerates all signings and cookies on each retry attempt
 */
async function axiosWithRetry(configBuilder, maxRetries = 5) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    // Regenerate config on each attempt (fresh signatures, cookies, user-agent)
    const config = await configBuilder();
    const response = await axios(config);
    
    // If 404, pass it through immediately
    if (response.status === 404) {
      return response;
    }
    
    // If 200, return success
    if (response.status === 200) {
      return response;
    }
    
    // If not 200 and not 404, retry (unless max retries reached)
    if (attempt < maxRetries) {
      console.log(`⚠️  Retry ${attempt}/${maxRetries - 1} - Status: ${response.status} - Regenerating signatures & cookies...`);
      continue;
    }
    
    // Max retries reached, return last response
    return response;
  }
}

// Robots.txt to discourage scanners
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send("User-agent: *\nDisallow: /\n");
});

// Cover image proxy: /cover/:filename -> https://i0.hdslb.com/bfs/archive/:filename
app.get("/cover/:filename", async (req, res) => {
  try {
    const { filename } = req.params;
    const targetUrl = `https://i0.hdslb.com/bfs/archive/${filename}`;

    const userAgent = userAgentGenerator().toString();

    // Generate random DedeUserID and DedeUserID__ckMd5
    const dedeUserID = Math.floor(Math.pow(Math.random(), 4) * 1000000000000);
    const dedeUserID__ckMd5 = crypto.randomBytes(8).toString('hex');

    const axiosConfig = {
      method: "GET",
      url: targetUrl,
      headers: {
        "User-Agent": userAgent,
        Referer: "https://www.bilibili.com/",
        Cookie: `DedeUserID=${dedeUserID}; DedeUserID__ckMd5=${dedeUserID__ckMd5}`,
      },
      responseType: "arraybuffer",
      timeout: config.proxy.timeout,
      validateStatus: () => true,
    };

    // Only add proxy agents if proxy is enabled
    if (httpAgent) axiosConfig.httpAgent = httpAgent;
    if (httpsAgent) axiosConfig.httpsAgent = httpsAgent;

    const response = await axios(axiosConfig);

    console.log(`Cover: ${response.status} - ${filename}`);

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
    res.set("Access-Control-Allow-Methods", "GET, OPTIONS");

    res.status(response.status).send(response.data);
  } catch (error) {
    console.error("Cover proxy error:", error);
    res.status(500).json({
      error: "Cover proxy request failed",
      message: error.message,
    });
  }
});

app.all("*", async (req, res) => {
  try {
    // Block root path access - disallow access to "/"
    if (req.path === "/") {
      console.log(`🚫 Blocked root access from ${req.ip}`);
      return res.status(404).json({ error: "Not found" });
    }

    const startTime = Date.now();
    let targetUrl = "";
    let shouldSign = true;

    // Handle /apivc requests
    if (req.path.startsWith("/apivc")) {
      targetUrl = `https://api.vc.bilibili.com${req.path.replace("/apivc", "")}`;
      shouldSign = false; // api.vc.bilibili.com does not require WBI signing
    } else {
      targetUrl = `https://api.bilibili.com${req.path}`;
      shouldSign = true;
    }

    // Determine Referer based on avid or bvid query parameters
    let referer = "https://www.bilibili.com/";
    if (req.query.avid) {
      // Extract the numeric part from avid (e.g., "av364108" -> "364108")
      const avidValue = req.query.avid.toString().replace(/^av/i, '');
      referer = `https://www.bilibili.com/video/av${avidValue}`;
    } else if (req.query.bvid) {
      referer = `https://www.bilibili.com/video/${req.query.bvid}`;
    } else if (req.query.aid) {
      referer = `https://www.bilibili.com/video/av${req.query.aid}`;
    }

    // Create a config builder function that regenerates everything on each call
    const buildAxiosConfig = async () => {
      let url = targetUrl;
      
      // For GET requests, sign the parameters if needed
      if (req.method === "GET") {
        let signedParams = req.query;
        
        if (shouldSign) {
          signedParams = await signWithWbi(req.query);
        }

        const queryString = Object.entries(signedParams)
          .map(
            ([key, value]) =>
              `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
          )
          .join("&");

        if (queryString) {
          url += `?${queryString}`;
        }
      }

      // Regenerate user agent
      const userAgent = userAgentGenerator().toString();

      let headers = {
        ...req.headers,
        "User-Agent": userAgent,
        Referer: referer,
        Origin: referer,
      };

      // Add SESSDATA cookie if configured for authenticated requests
      const extraCookies = [];
      if (config.bilibili.sessdata) {
        extraCookies.push(`SESSDATA=${config.bilibili.sessdata}`);
      }

      // Generate random DedeUserID and DedeUserID__ckMd5
      const dedeUserID = Math.floor(Math.pow(Math.random(), 4) * 1000000000000);
      const dedeUserID__ckMd5 = crypto.randomBytes(8).toString('hex');

      extraCookies.push(`DedeUserID=${dedeUserID}`);
      extraCookies.push(`DedeUserID__ckMd5=${dedeUserID__ckMd5}`);

      if (extraCookies.length > 0) {
        headers.Cookie = extraCookies.join('; ');
      }

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
        url: url,
        headers,
        data: req.body,
        timeout: config.proxy.timeout,
        validateStatus: () => true,
      };

      // Only add proxy agents if proxy is enabled
      if (httpAgent) axiosConfig.httpAgent = httpAgent;
      if (httpsAgent) axiosConfig.httpsAgent = httpsAgent;

      return axiosConfig;
    };

    const response = await axiosWithRetry(buildAxiosConfig);

    const endTime = Date.now();
    const timePassed = endTime - startTime;

    // Log status and time for all requests
    console.log(`${response.status} - ${timePassed}ms`);

    // Only log detailed info for non-200 responses
    if (response.status !== 200) {
      console.log(`❌ Non-200 response details:`);
      console.log(`  Method: ${req.method}`);
      console.log(`  Original URL: ${req.originalUrl}`);
      console.log(`  Status: ${response.status}`);
      console.log(`  Time: ${timePassed}ms`);
      console.log(`  Query params:`, req.query);
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

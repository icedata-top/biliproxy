export const config = {
  // Bilibili configuration
  bilibili: {
    // Optional: Add your SESSDATA cookie if you have one for authenticated requests
    sessdata: process.env.BILIBILI_SESSDATA || ""
  },
  
  // Server configuration  
  server: {
    port: process.env.PORT || 3000,
    host: process.env.HOST || '127.0.0.1'
  },
  
  // Proxy configuration
  proxy: {
    url: process.env.PROXY_URL || 'http://aaa:bbb@127.0.0.1:21990',
    timeout: parseInt(process.env.PROXY_TIMEOUT) || 30000
  },
  
  // Cache configuration
  cache: {
    wbiKeysExpiry: 8 * 60 * 60 // 8 hours in seconds
  }
};

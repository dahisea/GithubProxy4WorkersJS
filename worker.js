// 代理配置类
class ProxyConfig {
  constructor(baseDomain = 'sakiko') {
    this.baseDomain = baseDomain;

    // 域名映射配置
    this.domainMappings = {
      'api.github.com': 'api-gh',
      'gist.github.com': 'gist-gh',
      'raw.githubusercontent.com': 'rgh',
      'codeload.github.com': 'cl-gh',
      'github.githubassets.com': 'assets-gh',
      'avatars.githubusercontent.com': 'avatars-gh',
      'user-images.githubusercontent.com': 'img-gh',
      'private-user-images.githubusercontent.com': 'pimg-gh',
      'camo.githubusercontent.com': 'camo-gh',
      'cloud.githubusercontent.com': 'cloud-gh',
      'media.githubusercontent.com': 'media-gh',
      'objects.githubusercontent.com': 'objects-gh',
      'desktop.githubusercontent.com': 'desktop-gh',
      'favicons.githubusercontent.com': 'favicons-gh',
      'education.github.com': 'edu-gh',
      'central.github.com': 'central-gh',
      'git-lfs.github.com': 'lfs-gh',
      'community.github.com': 'community-gh',
      'release-assets.githubusercontent.com': 'releases-gh',
      'github.com': 'gh'
    };

    // 直接替换配置
    this.directReplacements = {
      'api.github.com': 'captive.apple.com',
      'alive.github.com': 'captive.apple.com',
      'live.github.com': 'captive.apple.com',
      'securitylab.github.com': 'captive.apple.com',
      'collector.github.com': 'captive.apple.com',
      'cdn.jsdelivr.net': 'testingcf.jsdelivr.net',
      'fastly.jsdelivr.net': 'testingcf.jsdelivr.net',
      'unpkg.com': 'unpkg.zhimg.com',
    };

    // 特殊URL映射
    this.specialUrlMappings = {
      '/': 'https://github.com/dahisea/GithubProxy4WorkersJS',
      '/login': 'https://github.com/dahisea/GithubProxy4WorkersJS',
      '/signup': 'https://github.com/dahisea/GithubProxy4WorkersJS',
    };

    // 需要重定向的路径
    this.redirectPaths = new Set([
      '/copilot', '/pricing', '/enterprise', '/premium-support',
      '/features/spark', '/features/model', '/features/copilot/copilot-business',
      '/security/advanced-security', '/team', '/organizations/new',
      '/marketplace', '/sponsors'
    ]);

    // 安全配置
    this.securityConfig = {
      allowedLanguages: new Set(['zh', 'zh-cn']),
      allowedCountries: new Set(['CN']),
      bannedASN: new Set(['AS8075', 'AS13335']),
    };
  }

  // 获取完整代理域名
  getFullProxyDomain(originalDomain) {
    const prefix = this.domainMappings[originalDomain];
    return prefix ? `${prefix}.${this.baseDomain}` : null;
  }

  // 获取原始域名
  getOriginalDomain(proxyDomain) {
    if (!proxyDomain.endsWith(`.${this.baseDomain}`)) {
      return null;
    }
    
    const prefix = proxyDomain.replace(`.${this.baseDomain}`, '');
    
    for (const [original, proxyPrefix] of Object.entries(this.domainMappings)) {
      if (prefix === proxyPrefix) {
        return original;
      }
    }
    
    return null;
  }

  // 获取目标主机
  getTargetHost(effectiveHost) {
    for (const [original, replacement] of Object.entries(this.directReplacements)) {
      if (effectiveHost === replacement || effectiveHost.endsWith(`.${replacement}`)) {
        return original;
      }
    }
    
    return this.getOriginalDomain(effectiveHost);
  }

  // 是否是直接替换域名
  isDirectReplacementDomain(host) {
    return Object.values(this.directReplacements).some(replacement =>
      host === replacement || host.endsWith(`.${replacement}`)
    );
  }
}

// 请求处理器类
class RequestProcessor {
  constructor(config) {
    this.config = config;
    this.cacheOptions = {
      // 通用缓存设置（适用于所有内容）
      universal: {
        browserTTL: 3600,       // 浏览器缓存1小时
        edgeTTL: 86400,        // CDN边缘缓存1天
        cacheKey: (request) => this.generateCacheKey(request)
      },
      // 静态资源特殊设置
      assets: {
        browserTTL: 31536000,   // 浏览器缓存1年
        edgeTTL: 31536000,     // CDN边缘缓存1年
        cacheKey: (request) => this.generateCacheKey(request, true)
      },
      // 可缓存的HTTP方法
      cacheableMethods: ['GET', 'HEAD'],
      // 可缓存的HTTP状态码
      cacheableStatusCodes: [200, 301, 302, 304, 404]
    };
  }

  // 生成缓存键
  generateCacheKey(request, includeVersion = false) {
    const url = new URL(request.url);
    const key = {
      url: url.href,
      headers: {
        'accept': request.headers.get('accept'),
        'accept-encoding': request.headers.get('accept-encoding'),
        'accept-language': request.headers.get('accept-language')
      }
    };

    if (includeVersion) {
      key.version = 'v1'; // 静态资源版本控制
    }

    return JSON.stringify(key);
  }

  // 主请求处理流程
  async processRequest(event) {
    const request = event.request;
    
    try {
      // 首先检查缓存（仅对可缓存方法）
      if (this.cacheOptions.cacheableMethods.includes(request.method)) {
        const cache = caches.default;
        const cachedResponse = await cache.match(request);
        
        if (cachedResponse) {
          // 克隆缓存响应并添加缓存命中头
          const headers = new Headers(cachedResponse.headers);
          headers.set('x-cache-status', 'HIT');
          return new Response(cachedResponse.body, {
            status: cachedResponse.status,
            headers
          });
        }
      }

      // 处理HTTP重定向到HTTPS
      const url = new URL(request.url);
      if (url.protocol === 'http:') {
        url.protocol = 'https:';
        return Response.redirect(url.href, 301);
      }

      // 检查是否需要阻止请求
      if (this.shouldBlock(request)) {
        return this.createErrorResponse('Hello World!', 200);
      }

      // 处理特殊URL
      const specialTarget = this.config.specialUrlMappings[url.pathname];
      if (specialTarget) {
        return this.handleSpecialUrl(event, request, specialTarget);
      }

      // 处理直接替换域名
      const effectiveHost = request.headers.get('Host') || url.host;
      if (this.config.isDirectReplacementDomain(effectiveHost)) {
        return this.handleDirectReplacement(event, request, effectiveHost);
      }

      // 处理代理前缀
      return this.handleProxyPrefix(event, request, effectiveHost);
      
    } catch (error) {
      console.error('请求处理错误:', error);
      return this.createErrorResponse(`服务器错误: ${error.message}`, 500);
    }
  }

  // 检查是否需要阻止请求
  shouldBlock(request) {
    const url = new URL(request.url);
    
    // 检查重定向路径
    if (this.config.redirectPaths.has(url.pathname)) {
      return true;
    }

    // 检查地理位置和ASN
    if (request.cf) {
      const { country, asn } = request.cf;
      
      if (country && !this.config.securityConfig.allowedCountries.has(country)) {
        return true;
      }
      
      if (asn && this.config.securityConfig.bannedASN.has(`AS${asn}`)) {
        return true;
      }
    }

    // 检查语言
    const acceptLanguage = request.headers.get('Accept-Language');
    if (acceptLanguage && !this.hasAllowedLanguage(acceptLanguage)) {
      return true;
    }

    return false;
  }

  // 检查允许的语言
  hasAllowedLanguage(acceptLanguage) {
    return acceptLanguage
      .split(',')
      .map(lang => lang.split(';')[0].trim().toLowerCase())
      .some(lang => 
        this.config.securityConfig.allowedLanguages.has(lang) || 
        this.config.securityConfig.allowedLanguages.has(lang.split('-')[0])
      );
  }

  // 处理特殊URL
  async handleSpecialUrl(event, request, targetUrl) {
    const originalUrl = new URL(request.url);
    const newUrl = new URL(targetUrl);
    newUrl.search = originalUrl.search;
    
    const headers = this.createProxyHeaders(request.headers, newUrl.host);
    const body = await this.processRequestBody(request);
    
    try {
      const response = await fetch(newUrl, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? body : undefined,
        redirect: 'manual'
      });
      
      // 克隆响应用于缓存
      const responseClone = response.clone();
      
      if (this.isCacheableResponse(responseClone)) {
        event.waitUntil(this.cacheResponse(request, responseClone));
      }
      
      return this.processResponse(response);
    } catch (error) {
      return this.createErrorResponse(`特殊URL代理错误: ${error.message}`, 502);
    }
  }

  // 处理直接替换域名
  async handleDirectReplacement(event, request, effectiveHost) {
    const originalDomain = this.config.getTargetHost(effectiveHost);
    if (!originalDomain) {
      return this.createErrorResponse('直接替换未找到', 404);
    }

    const url = new URL(request.url);
    url.host = originalDomain;
    
    const headers = this.createProxyHeaders(request.headers, originalDomain);
    const body = await this.processRequestBody(request);
    
    try {
      const response = await fetch(url, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? body : undefined,
        redirect: 'manual'
      });
      
      // 克隆响应用于缓存
      const responseClone = response.clone();
      
      if (this.isCacheableResponse(responseClone)) {
        event.waitUntil(this.cacheResponse(request, responseClone));
      }
      
      return this.processResponse(response);
    } catch (error) {
      return this.createErrorResponse(`直接替换错误: ${error.message}`, 502);
    }
  }

  // 处理代理前缀
  async handleProxyPrefix(event, request, effectiveHost) {
    const targetHost = this.config.getOriginalDomain(effectiveHost);
    if (!targetHost) {
      return this.createErrorResponse('域名未配置', 404);
    }

    const url = new URL(request.url);
    const newUrl = new URL(url.pathname, `https://${targetHost}`);
    newUrl.search = url.search;

    const headers = this.createProxyHeaders(request.headers, targetHost);
    const body = await this.processRequestBody(request);

    try {
      const response = await fetch(newUrl, {
        method: request.method,
        headers,
        body: request.method !== 'GET' && request.method !== 'HEAD' ? body : undefined,
        redirect: 'manual'
      });

      // 克隆响应用于缓存
      const responseClone = response.clone();
      
      if (this.isCacheableResponse(responseClone)) {
        event.waitUntil(this.cacheResponse(request, responseClone));
      }

      return this.processResponse(response);
    } catch (error) {
      return this.createErrorResponse(`代理错误: ${error.message}`, 502);
    }
  }

  // 处理请求体
  async processRequestBody(request) {
    if (request.method === 'GET' || request.method === 'HEAD') {
      return null;
    }

    const contentType = request.headers.get('content-type') || '';
    
    try {
      if (contentType.includes('application/json')) {
        const text = await request.text();
        return this.replaceDomainReferences(text, true);
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        const text = await request.text();
        return this.processFormData(text);
      }
      return request.body;
    } catch (error) {
      console.error('处理请求体错误:', error);
      return request.body;
    }
  }

  // 处理表单数据
  processFormData(text) {
    try {
      const formData = new URLSearchParams(text);
      const processedFormData = new URLSearchParams();
      
      for (const [key, value] of formData) {
        processedFormData.append(key, this.replaceDomainReferences(value, true));
      }
      
      return processedFormData.toString();
    } catch (error) {
      console.error('处理表单数据错误:', error);
      return text;
    }
  }

  // 创建代理头
  createProxyHeaders(originalHeaders, targetHost) {
    const headers = new Headers([
      ['Host', targetHost]
    ]);

    const safeHeaders = [
      'accept', 'accept-encoding', 'accept-language',
      'cache-control', 'content-type', 'content-length', 'user-agent',
      'x-requested-with'
    ];

    safeHeaders.forEach(header => {
      if (originalHeaders.has(header)) {
        headers.set(header, originalHeaders.get(header));
      }
    });

    const referer = originalHeaders.get('Referer');
    if (referer) {
      try {
        const refererUrl = new URL(referer);
        refererUrl.host = targetHost;
        headers.set('Referer', refererUrl.href);
      } catch (e) {
        headers.set('Referer', `https://${targetHost}/`);
      }
    }
    
    return headers;
  }

  // 处理响应
  async processResponse(response) {
    // 处理重定向
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      return this.handleRedirect(response);
    }

    const contentType = response.headers.get('content-type') || '';
    const headers = this.createResponseHeaders(response.headers);

    // 非文本内容直接返回
    if (!this.isTextContent(contentType)) {
      return new Response(response.body, { status: response.status, headers });
    }

    try {
      // 克隆响应以处理文本内容
      const responseClone = response.clone();
      let text = await responseClone.text();
      
      if (contentType.includes('html')) {
        text = this.addSecurityHeaders(text);
      }
      
      text = this.replaceDomainReferences(text);
      
      return new Response(text, { status: response.status, headers });
    } catch (error) {
      console.error('响应处理错误:', error);
      return new Response(response.body, { status: response.status, headers });
    }
  }

  // 处理重定向
  handleRedirect(response) {
    const location = response.headers.get('Location');
    if (!location) return response;

    const modifiedLocation = this.modifyLocationHeader(location);
    const headers = this.createResponseHeaders(response.headers);
    headers.set('Location', modifiedLocation);

    return new Response(response.body, { status: response.status, headers });
  }

  // 修改Location头
  modifyLocationHeader(location) {
    try {
      if (location.startsWith('/')) {
        return location;
      }

      const url = new URL(location);

      // 处理直接替换域名的重定向
      for (const [original, replacement] of Object.entries(this.config.directReplacements)) {
        if (url.host === original) {
          url.host = replacement;
          return url.toString();
        }
      }

      // 处理代理域名的重定向
      for (const [original, proxyPrefix] of Object.entries(this.config.domainMappings)) {
        if (url.host === original) {
          url.host = `${proxyPrefix}.${this.config.baseDomain}`;
          return url.toString();
        }
      }

      return url.toString();
    } catch (error) {
      console.error('修改Location头错误:', error);
      return location;
    }
  }

  // 检查是否是文本内容
  isTextContent(contentType) {
    return /text|json|javascript|xml|html|css/.test(contentType);
  }

  // 添加安全头到HTML
  addSecurityHeaders(html) {
    // 1. 删除不需要的meta标签
    const metaTagsToRemove = [
      '<meta\\s+http-equiv="x-pjax[^"]*"[^>]*>',
      '<meta\\s+name="route-[^"]*"[^>]*>',
      '<meta\\s+name="visitor-[^"]*"[^>]*>',
      '<meta\\s+name="octolytics-[^"]*"[^>]*>',
      '<meta\\s+name="turbo-[^"]*"[^>]*>',
      '<meta\\s+name="request-id"[^>]*>',
      '<meta\\s+name="html-safe-nonce"[^>]*>',
      '<meta\\s+name="fetch-nonce"[^>]*>',
      '<meta\\s+name="current-catalog-service-hash"[^>]*>',
      '<meta\\s+name="google-site-verification"[^>]*>',
      '<meta\\s+name="expected-hostname"[^>]*>',
      '<meta\\s+name="hostname"[^>]*>',
      '<meta\\s+name="theme-color"[^>]*>',
      '<link\\s+rel="dns-prefetch"[^>]*>',
      '<link\\s+rel="preconnect"[^>]*>'
    ];

    let cleanedHtml = html;
    for (const pattern of metaTagsToRemove) {
      cleanedHtml = cleanedHtml.replace(new RegExp(pattern, 'gi'), '');
    }

    // 2. 让所有<a>标签在新窗口打开
    cleanedHtml = cleanedHtml.replace(
      /<a\s+([^>]*)>/gi,
      (match, attributes) => {
        const withoutTarget = attributes.replace(/\btarget\s*=\s*["'][^"']*["']/gi, '');
        return `<a ${withoutTarget} target="_blank">`;
      }
    );

    // 3. 添加安全相关的meta标签
    const securityMetaTags = [
      '<meta name="referrer" content="no-referrer">',
      '<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">'
    ].join('');

    return cleanedHtml.replace(/<head[^>]*>/i, `$&${securityMetaTags}`);
  }

  // 替换域名引用
  replaceDomainReferences(text, isReverse = false) {
    let result = text;

    try {
      if (isReverse) {
        // 反向替换（代理域名→原始域名）
        for (const [original, replacement] of Object.entries(this.config.directReplacements)) {
          result = result.replace(
            new RegExp(`(https?:\\/\\/)${replacement.replace(/\./g, '\\.')}(\\/|$)`, 'gi'),
            `$1${original}$2`
          );
        }
        
        for (const [original, proxyPrefix] of Object.entries(this.config.domainMappings)) {
          const fullProxyDomain = `${proxyPrefix}.${this.config.baseDomain}`;
          result = result.replace(
            new RegExp(`(https?:\\/\\/)${fullProxyDomain.replace(/\./g, '\\.')}(\\/|$)`, 'gi'),
            `$1${original}$2`
          );
        }
      } else {
        // 正向替换（原始域名→代理域名）
        for (const [original, replacement] of Object.entries(this.config.directReplacements)) {
          result = result.replace(
            new RegExp(`(https?:\\/\\/)${original.replace(/\./g, '\\.')}(\\/|$)`, 'gi'),
            `$1${replacement}$2`
          );
        }
        
        for (const [original, proxyPrefix] of Object.entries(this.config.domainMappings)) {
          const fullProxyDomain = `${proxyPrefix}.${this.config.baseDomain}`;
          result = result.replace(
            new RegExp(`(https?:\\/\\/)${original.replace(/\./g, '\\.')}(\\/|$)`, 'gi'),
            `$1${fullProxyDomain}$2`
          );
        }
      }
    } catch (error) {
      console.error('替换域名引用错误:', error);
    }

    return result;
  }

  // 创建响应头
  createResponseHeaders(originalHeaders) {
    const headers = new Headers(originalHeaders);

    // 添加安全头
    const securityHeaders = {
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Cross-Origin-Embedder-Policy': 'unsafe-none',
      'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
      'Cache-Control': 'public, max-age=172800, stale-while-revalidate=86400'
    };

    Object.entries(securityHeaders).forEach(([key, value]) => {
      headers.set(key, value);
    });

    // 删除不需要的头
    ['connection', 'x-xss-protection', 'vary', 'content-security-policy', 'set-cookie', 'x-github-request-id'].forEach(header => headers.delete(header));

    return headers;
  }

  // 检查响应是否可缓存
  isCacheableResponse(response) {
    return this.cacheOptions.cacheableStatusCodes.includes(response.status);
  }

  // 缓存响应
  async cacheResponse(request, response) {
    try {
      const cache = caches.default;
      const contentType = response.headers.get('content-type') || '';
      
      // 确定使用哪种缓存规则
      const isAsset = contentType.includes('css') || 
                      contentType.includes('javascript') || 
                      contentType.includes('font') || 
                      contentType.includes('image');
      const cacheRule = isAsset ? this.cacheOptions.assets : this.cacheOptions.universal;
      
      // 创建专门用于缓存的新响应
      const responseToCache = new Response(response.body, {
        status: response.status,
        headers: new Headers(response.headers)
      });
      
      // 设置缓存控制头
      responseToCache.headers.set('Cache-Control', `public, max-age=${cacheRule.browserTTL}`);
      responseToCache.headers.set('CDN-Cache-Control', `max-age=${cacheRule.edgeTTL}`);
      responseToCache.headers.set('x-cache-status', 'MISS');
      responseToCache.headers.set('x-cache-key', cacheRule.cacheKey(request));
      
      // 存储到缓存
      await cache.put(cacheRule.cacheKey(request), responseToCache);
    } catch (error) {
      console.error('缓存错误:', error);
    }
  }

  // 创建错误响应
  createErrorResponse(message, status) {
    return new Response(JSON.stringify({
      error: message,
      status,
      timestamp: new Date().toISOString()
    }), {
      status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
}

// Worker事件监听
addEventListener('fetch', event => {
  const config = new ProxyConfig();
  const processor = new RequestProcessor(config);
  
  event.respondWith(processor.processRequest(event));
});

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduled());
});

async function handleScheduled() {
  console.log('定时任务执行于:', new Date().toISOString());
}
class ProxyConfig {
  constructor(baseDomain = 'sakiko') {
    this.baseDomain = baseDomain;

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

    this.specialUrlMappings = {
      '/': 'https://github.com/dahisea/GithubProxy4WorkersJS',
      '/login': 'https://github.com/dahisea/GithubProxy4WorkersJS',
      '/signup': 'https://github.com/dahisea/GithubProxy4WorkersJS',
    };

    this.redirectPaths = new Set([
      '/copilot', '/pricing', '/enterprise', '/premium-support',
      '/features/spark', '/features/model', '/features/copilot/copilot-business',
      '/security/advanced-security', '/team', '/organizations/new',
      '/marketplace', '/sponsors'
    ]);

    this.securityConfig = {
      allowedLanguages: new Set(['zh', 'zh-cn']),
      allowedCountries: new Set(['CN']),
      bannedASN: new Set(['AS8075', 'AS13335']),
    };
  }

  getFullProxyDomain(originalDomain) {
    const prefix = this.domainMappings[originalDomain];
    return prefix ? `${prefix}.${this.baseDomain}` : null;
  }

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
}

class RequestProcessor {
  constructor(config) {
    this.config = config;
  }

  async processRequest(request) {
    try {
      const url = new URL(request.url);
      
      if (this.shouldBlock(request)) {
        return this.createErrorResponse('Hello World!', 200);
      }

      if (url.protocol === 'http:') {
        url.protocol = 'https:';
        return Response.redirect(url.href, 301);
      }

      if (request.method === 'OPTIONS') {
        return this.handlePreflight();
      }

      const specialTarget = this.config.specialUrlMappings[url.pathname];
      if (specialTarget) {
        return this.handleSpecialUrl(request, specialTarget);
      }

      const effectiveHost = request.headers.get('Host') || url.host;

      if (this.isDirectReplacementDomain(effectiveHost)) {
        return this.handleDirectReplacement(request, effectiveHost);
      }

      return this.handleProxyPrefix(request, effectiveHost);
    } catch (error) {
      console.error('Request processing error:', error);
      return this.createErrorResponse(`Server Error: ${error.message}`, 500);
    }
  }

  shouldBlock(request) {
    const url = new URL(request.url);
    
    if (this.config.redirectPaths.has(url.pathname)) {
      return true;
    }

    if (request.cf) {
      const { country, asn } = request.cf;
      
      if (country && !this.config.securityConfig.allowedCountries.has(country)) {
        return true;
      }
      
      if (asn && this.config.securityConfig.bannedASN.has(`AS${asn}`)) {
        return true;
      }
    }

    const acceptLanguage = request.headers.get('Accept-Language');
    if (acceptLanguage && !this.hasAllowedLanguage(acceptLanguage)) {
      return true;
    }

    return false;
  }

  hasAllowedLanguage(acceptLanguage) {
    return acceptLanguage
      .split(',')
      .map(lang => lang.split(';')[0].trim().toLowerCase())
      .some(lang => 
        this.config.securityConfig.allowedLanguages.has(lang) || 
        this.config.securityConfig.allowedLanguages.has(lang.split('-')[0])
      );
  }

  handlePreflight() {
    return new Response(null, {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
        'Access-Control-Allow-Headers': '*',
        'Access-Control-Max-Age': '86400',
      }
    });
  }

  async handleSpecialUrl(request, targetUrl) {
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
      
      return this.processResponse(response);
    } catch (error) {
      return this.createErrorResponse(`Special URL proxy error: ${error.message}`, 502);
    }
  }

  isDirectReplacementDomain(host) {
    return Object.values(this.config.directReplacements).some(replacement =>
      host === replacement || host.endsWith(`.${replacement}`)
    );
  }

  getTargetHost(effectiveHost) {
    for (const [original, replacement] of Object.entries(this.config.directReplacements)) {
      if (effectiveHost === replacement || effectiveHost.endsWith(`.${replacement}`)) {
        return original;
      }
    }
    
    return this.config.getOriginalDomain(effectiveHost);
  }

  async handleDirectReplacement(request, effectiveHost) {
    const originalDomain = this.getTargetHost(effectiveHost);
    if (!originalDomain) {
      return this.createErrorResponse('Direct replacement not found', 404);
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
      
      return this.processResponse(response);
    } catch (error) {
      return this.createErrorResponse(`Direct replacement error: ${error.message}`, 502);
    }
  }

  async handleProxyPrefix(request, effectiveHost) {
    const targetHost = this.config.getOriginalDomain(effectiveHost);
    if (!targetHost) {
      return this.createErrorResponse('Domain not configured', 404);
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

      return this.processResponse(response);
    } catch (error) {
      return this.createErrorResponse(`Proxy error: ${error.message}`, 502);
    }
  }

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
      console.error('Error processing request body:', error);
      return request.body;
    }
  }

  processFormData(text) {
    try {
      const formData = new URLSearchParams(text);
      const processedFormData = new URLSearchParams();
      
      for (const [key, value] of formData) {
        processedFormData.append(key, this.replaceDomainReferences(value, true));
      }
      
      return processedFormData.toString();
    } catch (error) {
      console.error('Error processing form data:', error);
      return text;
    }
  }

  createProxyHeaders(originalHeaders, targetHost) {
    const headers = new Headers([
      ['Host', targetHost],
      ['Origin', `https://${targetHost}`]
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

  async processResponse(response) {
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      return this.handleRedirect(response);
    }

    const contentType = response.headers.get('content-type') || '';
    const headers = this.createResponseHeaders(response.headers);

    if (!this.isTextContent(contentType)) {
      return new Response(response.body, { status: response.status, headers });
    }

    try {
      let text = await response.text();
      
      if (contentType.includes('html')) {
        text = this.addSecurityHeaders(text);
      }
      
      text = this.replaceDomainReferences(text);
      
      return new Response(text, { status: response.status, headers });
    } catch (error) {
      console.error('Error processing response:', error);
      return new Response(response.body, { status: response.status, headers });
    }
  }

  handleRedirect(response) {
    const location = response.headers.get('Location');
    if (!location) return response;

    const modifiedLocation = this.modifyLocationHeader(location);
    const headers = this.createResponseHeaders(response.headers);
    headers.set('Location', modifiedLocation);

    return new Response(response.body, { status: response.status, headers });
  }

  modifyLocationHeader(location) {
    try {
      if (location.startsWith('/')) {
        return location;
      }

      const url = new URL(location);

      for (const [original, replacement] of Object.entries(this.config.directReplacements)) {
        if (url.host === original) {
          url.host = replacement;
          return url.toString();
        }
      }

      for (const [original, proxyPrefix] of Object.entries(this.config.domainMappings)) {
        if (url.host === original) {
          url.host = `${proxyPrefix}.${this.config.baseDomain}`;
          return url.toString();
        }
      }

      return url.toString();
    } catch (error) {
      console.error('Error modifying location header:', error);
      return location;
    }
  }

  isTextContent(contentType) {
    return /text|json|javascript|xml|html|css/.test(contentType);
  }

addSecurityHeaders(html) {
  // 1. 删除不需要的 meta 标签
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

  // 2. 让所有 <a> 标签在新窗口打开
  cleanedHtml = cleanedHtml.replace(
    /<a\s+([^>]*)>/gi,
    (match, attributes) => {
      // 如果已经有 target 属性，先移除
      const withoutTarget = attributes.replace(/\btarget\s*=\s*["'][^"']*["']/gi, '');
      // 添加 target="_blank"
      return `<a ${withoutTarget} target="_blank">`;
    }
  );

  // 3. 添加安全相关的 meta 标签
  const securityMetaTags = [
    '<meta name="referrer" content="no-referrer">',
    '<meta name="robots" content="noindex, nofollow, noarchive, nosnippet">'
  ].join('');

  return cleanedHtml.replace(/<head[^>]*>/i, `$&${securityMetaTags}`);
}

  replaceDomainReferences(text, isReverse = false) {
    let result = text;

    try {
      if (isReverse) {
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
      console.error('Error replacing domain references:', error);
    }

    return result;
  }

  createResponseHeaders(originalHeaders) {
    const headers = new Headers(originalHeaders);

    const securityHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Credentials': 'true',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'Cross-Origin-Embedder-Policy': 'unsafe-none',
      'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'SAMEORIGIN',
      'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
      'Cache-Control': 'public, max-age=172800, stale-while-revalidate=86400'
    };

    Object.entries(securityHeaders).forEach(([key, value]) => {
      headers.set(key, value);
    });

    ['content-security-policy', 'set-cookie', 'x-github-request-id'].forEach(header => headers.delete(header));

    return headers;
  }

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

addEventListener('fetch', event => {
  const config = new ProxyConfig();
  const processor = new RequestProcessor(config);
  
  event.respondWith(
    processor.processRequest(event.request).catch(error => {
      console.error('Unhandled error:', error);
      return new Response(JSON.stringify({
        error: 'Internal Server Error',
        message: error.message,
        timestamp: new Date().toISOString()
      }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*'
        }
      });
    })
  );
});

addEventListener('scheduled', event => {
  event.waitUntil(handleScheduled());
});

async function handleScheduled() {
  console.log('Health check completed at:', new Date().toISOString());
}
# Server-to-Server Integration Guide

This guide outlines the communication patterns between hamrah.app (Qwik server functions) and hamrah-api.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Browser       │    │   hamrah.app     │    │   hamrah-api    │
│   (hamrah.app)  │    │   (Qwik Server)  │    │   (Rust API)    │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • OAuth flows   │◄──►│ • Server render  │◄──►│ • Auth storage  │
│ • Client auth   │    │ • Middleware     │    │ • User data     │
│ • UI rendering  │    │ • SSR auth check │    │ • Token mgmt    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Communication Patterns

### 1. Client-Side Only (Direct Browser → API)
**Use for**: User-initiated actions, real-time updates
```typescript
// Frontend JavaScript (runs in browser)
const response = await fetch('https://api.hamrah.app/api/users/me', {
  credentials: 'include' // Sends session cookie
});
```

### 2. Server-Side Only (Qwik Server → API)
**Use for**: SSR authentication, middleware, server-side data fetching
```typescript
// Qwik server function
export const onRequest: RequestHandler = async ({ cookie, url }) => {
  // Forward session cookie to API for server-side validation
  const sessionCookie = cookie.get('session')?.value;
  
  const response = await fetch('https://api.hamrah.app/api/auth/sessions/validate', {
    headers: {
      'Cookie': `session=${sessionCookie}`,
      'User-Agent': 'hamrah-web-server/1.0'
    }
  });
  
  if (!response.ok) {
    throw redirect(302, '/login');
  }
  
  return response.json();
};
```

### 3. Hybrid (Server → API, then Client → API)
**Use for**: Initial SSR load, then client-side interactions
```typescript
// Server-side data loading
export const onGet: RequestHandler = async ({ cookie }) => {
  const user = await validateUserSession(cookie.get('session')?.value);
  return { user }; // Pass to component
};

// Client-side updates
const updateProfile = async (data) => {
  await fetch('https://api.hamrah.app/api/users/me', {
    method: 'PUT',
    credentials: 'include',
    body: JSON.stringify(data)
  });
};
```

## Recommended Patterns by Use Case

### Authentication & Session Management

#### ✅ Server-Side (Qwik → API)
```typescript
// middleware.ts - Server-side auth check
export const onRequest: RequestHandler = async ({ cookie, url }) => {
  const protectedPaths = ['/dashboard', '/settings', '/profile'];
  
  if (protectedPaths.some(path => url.pathname.startsWith(path))) {
    const sessionCookie = cookie.get('session')?.value;
    
    if (!sessionCookie) {
      throw redirect(302, '/login');
    }
    
    const response = await fetch('https://api.hamrah.app/api/auth/sessions/validate', {
      headers: { 'Cookie': `session=${sessionCookie}` }
    });
    
    if (!response.ok) {
      throw redirect(302, '/login');
    }
  }
};
```

#### ✅ Client-Side (Browser → API)
```typescript
// Login/logout actions
const handleLogin = async (provider: string, credential: string) => {
  const response = await fetch('https://api.hamrah.app/api/auth/web', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ provider, credential })
  });
  
  if (response.ok) {
    window.location.href = '/dashboard';
  }
};
```

### User Data Management

#### ✅ Server-Side Initial Load (Qwik → API)
```typescript
// route.tsx - SSR user data
export const useUserData = routeLoader$(async ({ cookie }) => {
  const sessionCookie = cookie.get('session')?.value;
  
  if (!sessionCookie) return null;
  
  const response = await fetch('https://api.hamrah.app/api/users/me', {
    headers: { 'Cookie': `session=${sessionCookie}` }
  });
  
  return response.ok ? await response.json() : null;
});
```

#### ✅ Client-Side Updates (Browser → API)
```typescript
// User profile updates
const updateUser = routeAction$(async (data, { cookie }) => {
  return await fetch('https://api.hamrah.app/api/users/me', {
    method: 'PUT',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  });
});
```

### Data Fetching Patterns

#### ✅ Server-Side for SEO/Performance
```typescript
// For data that needs to be server-rendered
export const useInitialData = routeLoader$(async ({ cookie }) => {
  const sessionCookie = cookie.get('session')?.value;
  
  const [user, preferences] = await Promise.all([
    fetch('https://api.hamrah.app/api/users/me', {
      headers: { 'Cookie': `session=${sessionCookie}` }
    }),
    fetch('https://api.hamrah.app/api/users/me/preferences', {
      headers: { 'Cookie': `session=${sessionCookie}` }
    })
  ]);
  
  return {
    user: await user.json(),
    preferences: await preferences.json()
  };
});
```

#### ✅ Client-Side for Interactions
```typescript
// For dynamic, user-triggered actions
const refreshData = $(() => {
  fetch('https://api.hamrah.app/api/users/me/tokens', {
    credentials: 'include'
  }).then(response => response.json());
});
```

## Security Considerations

### Server-Side Calls
```typescript
// ✅ Good: Forward session cookie for server-side validation
const validateServerSide = async (sessionCookie: string) => {
  return await fetch('https://api.hamrah.app/api/auth/sessions/validate', {
    headers: {
      'Cookie': `session=${sessionCookie}`,
      'User-Agent': 'hamrah-web-server/1.0',
      'X-Forwarded-For': clientIP // If available
    }
  });
};

// ❌ Bad: Don't store or log sensitive cookies
console.log('Session:', sessionCookie); // Never do this
```

### Client-Side Calls
```typescript
// ✅ Good: Use credentials for automatic cookie handling
fetch('https://api.hamrah.app/api/users/me', {
  credentials: 'include' // Browser handles cookie automatically
});

// ❌ Bad: Don't manually handle session cookies client-side
fetch('https://api.hamrah.app/api/users/me', {
  headers: { 'Cookie': document.cookie } // Never do this
});
```

## Performance Optimization

### Caching Strategy
```typescript
// Server-side caching for expensive operations
const cache = new Map();

export const getCachedUserData = async (sessionCookie: string) => {
  if (cache.has(sessionCookie)) {
    return cache.get(sessionCookie);
  }
  
  const response = await fetch('https://api.hamrah.app/api/users/me', {
    headers: { 'Cookie': `session=${sessionCookie}` }
  });
  
  const userData = await response.json();
  cache.set(sessionCookie, userData);
  
  // Cache for 5 minutes
  setTimeout(() => cache.delete(sessionCookie), 5 * 60 * 1000);
  
  return userData;
};
```

### Request Batching
```typescript
// Batch multiple API calls server-side
export const loadPageData = routeLoader$(async ({ cookie }) => {
  const sessionCookie = cookie.get('session')?.value;
  const headers = { 'Cookie': `session=${sessionCookie}` };
  
  const [user, tokens, preferences] = await Promise.all([
    fetch('https://api.hamrah.app/api/users/me', { headers }),
    fetch('https://api.hamrah.app/api/users/me/tokens', { headers }),
    fetch('https://api.hamrah.app/api/users/me/preferences', { headers })
  ]);
  
  return {
    user: await user.json(),
    tokens: await tokens.json(),
    preferences: await preferences.json()
  };
});
```

## Error Handling

### Server-Side Error Handling
```typescript
export const safeApiCall = async (url: string, sessionCookie?: string) => {
  try {
    const response = await fetch(`https://api.hamrah.app${url}`, {
      headers: sessionCookie ? { 'Cookie': `session=${sessionCookie}` } : {}
    });
    
    if (response.status === 401) {
      throw redirect(302, '/login');
    }
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('API call failed:', error);
    throw error;
  }
};
```

### Client-Side Error Handling
```typescript
const handleApiError = (error: Response) => {
  if (error.status === 401) {
    window.location.href = '/login';
  } else if (error.status === 403) {
    // Handle permission errors
  } else {
    // Handle other errors
  }
};
```

## Summary

### Use Server-Side (Qwik → API) for:
- ✅ Authentication middleware
- ✅ SSR data loading
- ✅ SEO-critical content
- ✅ Initial page load optimization
- ✅ Security-sensitive operations

### Use Client-Side (Browser → API) for:
- ✅ User interactions
- ✅ Real-time updates
- ✅ Form submissions
- ✅ Dynamic content loading
- ✅ Progressive enhancement

### Avoid:
- ❌ Client-side session validation
- ❌ Server-side cookie manipulation
- ❌ Logging sensitive data
- ❌ Unnecessary server round-trips
- ❌ Blocking UI on server calls
# Qwik Server-Side Helper Functions

These helper functions can be added to your hamrah-web project to simplify server-side API integration.

## Installation

Create `src/lib/api-helpers.ts` in your hamrah-web project:

```typescript
// src/lib/api-helpers.ts

export interface ApiUser {
  id: string;
  email: string;
  name: string | null;
  picture: string | null;
  auth_method: string | null;
  created_at: string;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Makes authenticated API calls from Qwik server functions
 */
export async function apiCall<T = any>(
  endpoint: string,
  options: {
    method?: 'GET' | 'POST' | 'PUT' | 'DELETE';
    body?: any;
    sessionCookie?: string;
    headers?: Record<string, string>;
  } = {}
): Promise<ApiResponse<T>> {
  const { method = 'GET', body, sessionCookie, headers = {} } = options;
  
  const requestHeaders: Record<string, string> = {
    'User-Agent': 'hamrah-web-server/1.0',
    ...headers,
  };
  
  // Forward session cookie for authentication
  if (sessionCookie) {
    requestHeaders['Cookie'] = `session=${sessionCookie}`;
  }
  
  // Add content type for POST/PUT requests
  if (body && (method === 'POST' || method === 'PUT')) {
    requestHeaders['Content-Type'] = 'application/json';
  }
  
  try {
    const response = await fetch(`https://api.hamrah.app${endpoint}`, {
      method,
      headers: requestHeaders,
      body: body ? JSON.stringify(body) : undefined,
    });
    
    const data = await response.json();
    
    if (!response.ok) {
      return {
        success: false,
        error: data.error || `HTTP ${response.status}`,
      };
    }
    
    return {
      success: true,
      data,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Validates user session server-side
 */
export async function validateSession(sessionCookie?: string): Promise<ApiUser | null> {
  if (!sessionCookie) return null;
  
  const response = await apiCall<{ user: ApiUser }>('/api/auth/sessions/validate', {
    sessionCookie,
  });
  
  return response.success ? response.data?.user || null : null;
}

/**
 * Gets current user data server-side
 */
export async function getCurrentUser(sessionCookie?: string): Promise<ApiUser | null> {
  if (!sessionCookie) return null;
  
  const response = await apiCall<ApiUser>('/api/users/me', {
    sessionCookie,
  });
  
  return response.success ? response.data || null : null;
}

/**
 * Updates user profile server-side
 */
export async function updateUserProfile(
  updates: { name?: string; picture?: string },
  sessionCookie?: string
): Promise<ApiUser | null> {
  if (!sessionCookie) return null;
  
  const response = await apiCall<ApiUser>('/api/users/me', {
    method: 'PUT',
    body: updates,
    sessionCookie,
  });
  
  return response.success ? response.data || null : null;
}

/**
 * Gets user's active tokens server-side
 */
export async function getUserTokens(sessionCookie?: string) {
  if (!sessionCookie) return null;
  
  const response = await apiCall('/api/users/me/tokens', {
    sessionCookie,
  });
  
  return response.success ? response.data : null;
}
```

## Usage Examples

### 1. Authentication Middleware

```typescript
// src/middleware.ts
import { RequestHandler } from '@builder.io/qwik-city';
import { validateSession } from '~/lib/api-helpers';

export const onRequest: RequestHandler = async ({ cookie, url, redirect }) => {
  const protectedPaths = ['/dashboard', '/settings', '/profile'];
  
  if (protectedPaths.some(path => url.pathname.startsWith(path))) {
    const sessionCookie = cookie.get('session')?.value;
    const user = await validateSession(sessionCookie);
    
    if (!user) {
      throw redirect(302, '/login');
    }
  }
};
```

### 2. Route Loader (SSR Data Fetching)

```typescript
// src/routes/dashboard/index.tsx
import { routeLoader$ } from '@builder.io/qwik-city';
import { getCurrentUser, getUserTokens } from '~/lib/api-helpers';

export const useUserData = routeLoader$(async ({ cookie }) => {
  const sessionCookie = cookie.get('session')?.value;
  
  const [user, tokens] = await Promise.all([
    getCurrentUser(sessionCookie),
    getUserTokens(sessionCookie),
  ]);
  
  return { user, tokens };
});

export default component$(() => {
  const userData = useUserData();
  
  return (
    <div>
      <h1>Welcome, {userData.value.user?.name}!</h1>
      <p>You have {userData.value.tokens?.tokens?.length || 0} active sessions</p>
    </div>
  );
});
```

### 3. Route Action (Form Handling)

```typescript
// src/routes/settings/index.tsx
import { routeAction$, routeLoader$ } from '@builder.io/qwik-city';
import { getCurrentUser, updateUserProfile } from '~/lib/api-helpers';

export const useUser = routeLoader$(async ({ cookie, redirect }) => {
  const sessionCookie = cookie.get('session')?.value;
  const user = await getCurrentUser(sessionCookie);
  
  if (!user) {
    throw redirect(302, '/login');
  }
  
  return user;
});

export const useUpdateProfile = routeAction$(async (data, { cookie }) => {
  const sessionCookie = cookie.get('session')?.value;
  const updatedUser = await updateUserProfile(
    {
      name: data.name as string,
      picture: data.picture as string,
    },
    sessionCookie
  );
  
  return { success: !!updatedUser, user: updatedUser };
});

export default component$(() => {
  const user = useUser();
  const updateProfile = useUpdateProfile();
  
  return (
    <div>
      <h1>Settings</h1>
      <Form action={updateProfile}>
        <input
          name="name"
          value={user.value.name || ''}
          placeholder="Your name"
        />
        <input
          name="picture"
          value={user.value.picture || ''}
          placeholder="Profile picture URL"
        />
        <button type="submit">Update Profile</button>
      </Form>
      
      {updateProfile.value?.success && (
        <p>Profile updated successfully!</p>
      )}
    </div>
  );
});
```

### 4. Protected Route HOC

```typescript
// src/lib/protected-route.tsx
import { component$, Slot } from '@builder.io/qwik';
import { routeLoader$ } from '@builder.io/qwik-city';
import { getCurrentUser } from './api-helpers';

export const useRequireAuth = routeLoader$(async ({ cookie, redirect }) => {
  const sessionCookie = cookie.get('session')?.value;
  const user = await getCurrentUser(sessionCookie);
  
  if (!user) {
    throw redirect(302, '/login');
  }
  
  return user;
});

export const ProtectedRoute = component$(() => {
  const user = useRequireAuth();
  
  return (
    <div>
      <header>
        <p>Logged in as: {user.value.email}</p>
      </header>
      <main>
        <Slot />
      </main>
    </div>
  );
});

// Usage in routes:
// src/routes/dashboard/layout.tsx
export default component$(() => {
  return (
    <ProtectedRoute>
      <Slot />
    </ProtectedRoute>
  );
});
```

### 5. Client-Side Auth Actions

```typescript
// src/lib/client-auth.ts
/**
 * Client-side authentication functions (run in browser)
 */

export async function loginWithGoogle(credential: string) {
  const response = await fetch('https://api.hamrah.app/api/auth/web', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ provider: 'google', credential }),
  });
  
  if (response.ok) {
    window.location.href = '/dashboard';
  } else {
    const error = await response.json();
    throw new Error(error.error || 'Login failed');
  }
}

export async function logout() {
  await fetch('https://api.hamrah.app/api/auth/sessions/logout', {
    method: 'POST',
    credentials: 'include',
  });
  
  window.location.href = '/';
}

export async function getCurrentUserClient() {
  const response = await fetch('https://api.hamrah.app/api/users/me', {
    credentials: 'include',
  });
  
  return response.ok ? await response.json() : null;
}
```

## Best Practices

### 1. Error Handling
```typescript
export const useProtectedData = routeLoader$(async ({ cookie, redirect }) => {
  const sessionCookie = cookie.get('session')?.value;
  
  try {
    const user = await getCurrentUser(sessionCookie);
    
    if (!user) {
      throw redirect(302, '/login');
    }
    
    return { user, error: null };
  } catch (error) {
    console.error('Failed to load user data:', error);
    return { user: null, error: 'Failed to load user data' };
  }
});
```

### 2. Caching
```typescript
// Simple in-memory cache for server-side calls
const userCache = new Map<string, { user: ApiUser; timestamp: number }>();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

export async function getCachedUser(sessionCookie: string): Promise<ApiUser | null> {
  const cached = userCache.get(sessionCookie);
  
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.user;
  }
  
  const user = await getCurrentUser(sessionCookie);
  
  if (user) {
    userCache.set(sessionCookie, { user, timestamp: Date.now() });
  }
  
  return user;
}
```

### 3. Type Safety
```typescript
// Define strict types for your API responses
export interface UserTokenInfo {
  id: string;
  platform: string;
  user_agent: string | null;
  last_used: string | null;
  created_at: string;
  expires_at: string;
}

export interface UserTokensResponse {
  success: boolean;
  tokens: UserTokenInfo[];
}
```
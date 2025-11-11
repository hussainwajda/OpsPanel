// Utility for authentication cookie management and validation
export const getCookie = (name) => {
  const cookies = document.cookie.split(';');
  for (let i = 0; i < cookies.length; i++) {
    const cookie = cookies[i].trim();
    if (cookie.startsWith(name + '=')) {
      return cookie.substring(name.length + 1);
    }
  }
  return null;
};

// Remove all browser cookies
export const clearAllCookies = () => {
  document.cookie.split(";").forEach((c) => {
    document.cookie = c
      .replace(/^ +/, "")
      .replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
  });
};

// Check local authentication state
export const isAuthenticated = () => {
  // Quick check for login attempt
  const hasAnyCookies = getCookie('userEmail') || getCookie('deviceToken') || getCookie('username');
  
  // Immediate false if no cookies exist
  if (!hasAnyCookies) {
    return false;
  }
  
  const requiredCookies = ['userEmail', 'deviceToken', 'username'];
  
  // Validate all required cookies
  for (const cookieName of requiredCookies) {
    if (!getCookie(cookieName)) {
      return false;
    }
  }
  
  return true;
};

// Prevent concurrent server validation
let isValidatingWithServer = false;

// Validate authentication with backend
export const validateAuthWithServer = async () => {
  // Prevent multiple simultaneous requests
  if (isValidatingWithServer) {
    return false;
  }
  
  try {
    isValidatingWithServer = true;
    
    // Retrieve stored credentials
    const email = getCookie('userEmail');
    const username = getCookie('username');
    
    // Fail if critical cookies missing
    if (!email || !username) {
      return false;
    }
    
    // Generate validation token
    const { generateToken } = await import('./generateToken.js');
    const deviceToken = await generateToken();
    
    // Send authentication validation request
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL}/api/validate-auth/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Device-Token": deviceToken
        },
        body: JSON.stringify({
          email,
          username
        })
      }
    );
    
    // Reject on non-200 response
    if (!response.ok) {
      const errorData = await response.json();
      return false;
    }
    
    const data = await response.json();
    
    // Update device token
    const { setCookie } = await import('./generateToken.js');
    const cookieOptions = { 
      expires: 7,
      path: '/' 
    };
    setCookie('deviceToken', deviceToken, cookieOptions);
    
    return true;
    
  } catch (error) {
    // Treat any errors as auth failure
    return false;
  } finally {
    // Reset validation flag
    isValidatingWithServer = false;
  }
};

// Comprehensive authentication verification
export const checkAuth = async (includeServerCheck = false) => {
  // Skip check if no auth cookies exist
  if (!getCookie('userEmail') && !getCookie('deviceToken') && !getCookie('username')) {
    return false;
  }
  
  const userEmail = getCookie('userEmail');
  const deviceToken = getCookie('deviceToken');
  const username = getCookie('username');
  
  // Clear inconsistent cookie states
  if (!userEmail || !deviceToken || !username) {
    clearAllCookies();
    return false;
  }
  
  // Optional server-side validation
  if (includeServerCheck) {
    const serverAuthValid = await validateAuthWithServer();
    
    // Clear cookies if server validation fails
    if (!serverAuthValid) {
      clearAllCookies();
      return false;
    }
  }
  
  return true;
};

export default checkAuth;
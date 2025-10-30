import CryptoJS from 'crypto-js';

// Use the same secret key as password encryption
const SECRET_KEY = import.meta.env.VITE_AES_AUTH_PASSWORD_KEY;

export const generateToken = () => {
  try {
    // Combination of browser and device characteristics
    const userAgent = navigator.userAgent;
    const screenResolution = `${window.screen.width}x${window.screen.height}`;
    const colorDepth = window.screen.colorDepth;
    const hardwareConcurrency = navigator.hardwareConcurrency || 'unknown';
    const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
    
    // Generate a unique identifier using current timestamp and random values
    const timestamp = Date.now().toString();
    const randomPart = Math.random().toString(36).substring(2, 15);
    
    // Create a token string of combined characteristics
    const tokenData = `${userAgent}|${screenResolution}|${colorDepth}|${hardwareConcurrency}|${timezone}|${timestamp}|${randomPart}`;
    
    // Encrypt the token data using AES-256
    const encryptedToken = CryptoJS.AES.encrypt(tokenData, SECRET_KEY).toString();
    
    return Promise.resolve(encryptedToken);
  } catch (error) {
    console.error('Token generation error:', error);
    return Promise.reject('Failed to generate token');
  }
};

// Decrypt Token (if needed)
export const decryptToken = (encryptedToken) => {
  try {
    const bytes = CryptoJS.AES.decrypt(encryptedToken, SECRET_KEY);
    const decryptedToken = bytes.toString(CryptoJS.enc.Utf8);
    return decryptedToken;
  } catch (error) {
    console.error('Token decryption error:', error);
    return null;
  }
};

// Function to set cookie
export const setCookie = (name, value, options = {}) => {
  const defaultOptions = {
    path: '/',
    expires: 7 // Default 7 days
  };

  const mergedOptions = { ...defaultOptions, ...options };
  
  const date = new Date();
  date.setTime(date.getTime() + (mergedOptions.expires * 24 * 60 * 60 * 1000));
  
  const expires = `expires=${date.toUTCString()}`;
  document.cookie = `${name}=${value};${expires};path=${mergedOptions.path};SameSite=Strict`;
};

// Function to get cookie
export const getCookie = (name) => {
  const cookieName = `${name}=`;
  const decodedCookie = decodeURIComponent(document.cookie);
  const cookieArray = decodedCookie.split(';');
  
  for(let i = 0; i < cookieArray.length; i++) {
    let cookie = cookieArray[i];
    while (cookie.charAt(0) === ' ') {
      cookie = cookie.substring(1);
    }
    if (cookie.indexOf(cookieName) === 0) {
      return cookie.substring(cookieName.length, cookie.length);
    }
  }
  return '';
};
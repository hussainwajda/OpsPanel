import React, { useEffect, useState, useRef } from 'react'
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom'
import Auth from './pages/Auth.jsx'
import Home from './pages/Home.jsx'
import NavBar from './components/NavBar.jsx'
import { checkAuth, isAuthenticated } from './utils/checkAuth.js'

// Middleware to protect routes from unauthenticated access
// const ProtectedRoute = ({ children }) => {
//   const authenticated = isAuthenticated();
  
//   Redirect to auth if not authenticated
//   if (!authenticated) {
//     return <Navigate to="/auth" replace />;
//   }
  
//   return children;
// };

// Prevents authenticated users from accessing login page
const AuthRoute = ({ children }) => {
  const authenticated = isAuthenticated();

  // Redirect to home if already authenticated
  if (authenticated) {
    return <Navigate to="/" replace />;
  }

  return children;
};

// Central layout and authentication management
const AppLayout = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [authState, setAuthState] = useState(isAuthenticated());
  const isCheckingRef = useRef(false);
  const initialRenderDoneRef = useRef(false);
  const initialAuthPerformedRef = useRef(false);
  const showNavBar = location.pathname !== '/auth';
  
  // Comprehensive server-side authentication validation
  const performAuthCheck = async () => {
    // Prevent multiple concurrent auth checks
    if (isCheckingRef.current) {
      return false;
    }
    
    // Validate authentication status with server
    if (isAuthenticated()) {
      try {
        isCheckingRef.current = true;
        
        // Perform full authentication validation
        const authStatus = await checkAuth(true);
        setAuthState(authStatus);
        
        // Redirect if authentication fails
        if (!authStatus && location.pathname !== '/auth') {
          navigate('/auth');
        }
        
        return authStatus;
      } finally {
        // Reset checking flag
        isCheckingRef.current = false;
      }
    }
    
    // Update state if not authenticated
    setAuthState(false);
    return false;
  };
  
  // Initial authentication setup on component mount
  useEffect(() => {
    // Validate authentication on initial load
    if (isAuthenticated() && location.pathname !== '/auth' && !initialAuthPerformedRef.current) {
      initialAuthPerformedRef.current = true;
      performAuthCheck();
      
      // Defer initial render completion to avoid navigation conflicts
      setTimeout(() => {
        initialRenderDoneRef.current = true;
      });
    } else {
      // Mark initialization as complete
      setTimeout(() => {
        initialRenderDoneRef.current = true;
      });
    }
    
    // Cleanup function (intentionally minimal)
    return () => {};
  }, []); // Run only on initial mount
  
  // Handle authentication on route changes
  useEffect(() => {
    // Skip during initial render
    if (!initialRenderDoneRef.current) {
      return;
    }
    
    // Prevent access to auth page when already authenticated
    if (location.pathname === '/auth' && isAuthenticated()) {
      navigate('/', { replace: true });
      return;
    }
    
    // Perform auth check on protected routes
    if (location.pathname !== '/auth' && isAuthenticated()) {
      // Use timeout to avoid potential race conditions
      setTimeout(() => {
        performAuthCheck();
      }, 100);
    } else if (!isAuthenticated()) {
      setAuthState(false);
    }
  }, [location.pathname, navigate]);
  
  // Periodic authentication validation
  useEffect(() => {
    // Skip for auth page
    if (location.pathname === '/auth') {
      return;
    }
    
    // Set up regular auth status check
    const interval = setInterval(() => {
      if (isAuthenticated()) {
        performAuthCheck();
      }
    }, 5 * 60 * 1000); // Check every 5 minutes
    
    // Clean up interval
    return () => clearInterval(interval);
  }, [location.pathname]);
  
  // Redirect handler for authentication
  const handleRedirectToSignIn = () => {
    navigate('/auth');
  };
  
  return (
    <>
      {showNavBar && <NavBar isAuthenticated={authState} />}
      <Routes>
        {/* Authentication route with access restrictions */}
        <Route path="/auth" element={<AuthRoute><Auth /></AuthRoute>} />
        <Route 
          path="/" 
          element={
            <Home 
              isAuthenticated={authState} 
              onRedirectToSignIn={handleRedirectToSignIn}
              onAuthCheck={performAuthCheck}
            />
          } 
        />
        
        {/* Fallback route to home */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
};

// Main application wrapper
const App = () => {
  return (
    <Router>
      <AppLayout />
    </Router>
  );
};

export default App;
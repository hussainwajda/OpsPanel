import React, { useState, useEffect, useRef } from 'react';
import { 
  User, 
  LogOut, 
  Menu
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';

const NavBar = ({ isAuthenticated }) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [username, setUsername] = useState('');
  const [firstInitial, setFirstInitial] = useState('');
  const navigate = useNavigate();
  const dropdownRef = useRef(null);
  const buttonRef = useRef(null);

  // Retrieve and validate username from cookies
  useEffect(() => {
    const checkAuth = () => {
      // Validate username only when authenticated
      if (isAuthenticated) {
        const cookies = document.cookie.split('; ');
        const usernameCookie = cookies.find(cookie => cookie.startsWith('username='));
        
        if (usernameCookie) {
          const [_, value] = usernameCookie.split('=');
          setUsername(value);
          setFirstInitial(value.charAt(0).toUpperCase());
        } else {
          // Handle authentication inconsistency
          setUsername('');
          setFirstInitial('');
        }
      } else {
        // Clear username when not authenticated
        setUsername('');
        setFirstInitial('');
      }
    };

    checkAuth();
    
    // Frequent auth checks for responsive UI
    const interval = setInterval(checkAuth, 200);

    return () => clearInterval(interval);
  }, [isAuthenticated]);

  // Manage dropdown outside click behavior
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        isMenuOpen && 
        dropdownRef.current && 
        !dropdownRef.current.contains(event.target) &&
        buttonRef.current && 
        !buttonRef.current.contains(event.target)
      ) {
        setIsMenuOpen(false);
      }
    };

    // Add/remove outside click listener dynamically
    if (isMenuOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isMenuOpen]);

  // Logout handler with cleanup
  const handleLogout = () => {
    // Clear local storage and cookies
    localStorage.clear();

    // Invalidate all cookies
    document.cookie.split(";").forEach((c) => {
      document.cookie = c
        .replace(/^ +/, "")
        .replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
    });

    // Notify user and redirect
    toast.success('Logged out successfully!');
    navigate('/auth');
  };

  // Validate authentication state and required cookies
  const checkRequiredCookies = () => {
    // Check parent authentication state
    if (!isAuthenticated) {
      return false;
    }

    // Verify all required cookies
    const cookies = document.cookie.split('; ');
    const requiredCookies = ['deviceToken', 'userEmail', 'username'];
    
    // Ensure all required cookies exist
    for (const requiredCookie of requiredCookies) {
      if (!cookies.some(cookie => cookie.startsWith(`${requiredCookie}=`))) {
        return false;
      }
    }
    
    return true;
  };

  // Profile button click handler with authentication check
  const handleProfileButtonClick = () => {
    // Validate authentication and cookies
    if (!checkRequiredCookies()) {
      // Clear local storage on auth failure
      localStorage.clear();
      
      // Redirect to login
      navigate('/auth');
      return;
    }
    
    // Toggle dropdown for authenticated users
    setIsMenuOpen(!isMenuOpen);
  };

  // Dashboard panel toggle
  const toggleDashboard = () => {
    if (window.dashboardState) {
      const currentState = window.dashboardState.getIsDashboardOpen();
      window.dashboardState.setIsDashboardOpen(!currentState);
    }
  };

  // Truncate username for display
  const displayUsername = username ? username.slice(0, 10) : '';

  return (
    <nav className="bg-black/40 backdrop-blur-xl border-b border-gray-900/50 fixed top-0 left-0 right-0 z-50">
      <div className="max-w-full mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          {/* Logo and Mobile Menu */}
          <div className="flex items-center">
            {/* Mobile dashboard toggle */}
            <button 
              className="text-gray-400 hover:text-white cursor-pointer mr-3 md:hidden"
              onClick={toggleDashboard}
              aria-label="Toggle dashboard menu"
            >
              <Menu className="h-6 w-6" />
            </button>
            <span className="text-white block font-bold text-2xl">ServerMaster</span>
          </div>

          {/* User Menu */}
          <div className="flex items-center">
            {/* Profile dropdown */}
            <div className="relative">
              <button 
                ref={buttonRef}
                onClick={handleProfileButtonClick}
                className="flex items-center text-sm cursor-pointer rounded-lg px-2 py-1 hover:bg-white/10 focus:outline-none"
              >
                <span className="sr-only">Open user menu</span>
                <div className={`rounded-full h-8 w-8 flex items-center justify-center ${isAuthenticated ? 'bg-gray-700' : 'bg-gray-900'}`}>
                  {firstInitial && isAuthenticated ? (
                    <span className="text-white font-bold text-lg">{firstInitial}</span>
                  ) : (
                    <User className="h-5 w-5 text-gray-300" />
                  )}
                </div>
                {/* Username display */}
                {displayUsername && isAuthenticated && (
                  <span className="ml-2 text-white font-medium hidden md:block">
                    {displayUsername}
                  </span>
                )}
              </button>

              {/* Dropdown menu */}
              {isMenuOpen && isAuthenticated && (
                <div 
                  ref={dropdownRef}
                  className="origin-top-right absolute right-0 mt-4 w-36 rounded-xl shadow-lg border border-gray-900/50 z-50 bg-black/95 backdrop-blur-sm"
                >
                  <button
                    className="block cursor-pointer w-full text-left px-4 py-3 text-sm text-red-400 hover:bg-white/10 hover:text-red-300 rounded-xl"
                    onClick={handleLogout}
                  >
                    <div className="flex items-center">
                      <LogOut className="h-4 w-4 mr-2" />
                      Sign out
                    </div>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default NavBar;
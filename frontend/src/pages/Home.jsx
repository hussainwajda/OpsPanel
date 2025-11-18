import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { 
  Server, Cpu, X,
  LogIn, Loader,
  Package, FolderOpen,
  Terminal, InfoIcon
} from 'lucide-react';
import ToastContainer from '../components/ToastContainer.jsx';
import SSHConnectionCard from '../components/dashboard/SSHConnectionCard.jsx';
import AppInstall from '../components/dashboard/AppInstall.jsx';
import FileExplorer from '../components/dashboard/FileExplorer.jsx';
import Monitoring from '../components/dashboard/Monitoring.jsx';
import CustomCommands from '../components/dashboard/CustomCommands.jsx';
import toast from 'react-hot-toast';
import CryptoJS from 'crypto-js';
import CustomScrollbar from '../components/CustomScrollbar.jsx';
import ConnectionHistory from '../components/dashboard/connectionHistory.jsx';

// Memoized tab content with authenticated access control
const MemoizedTabContent = React.memo(({ tab, isAuthenticated, onRedirectToSignIn, componentProps }) => {
  // Require authentication for all tabs
  if (!isAuthenticated) {
    return <SignInCard onRedirectToSignIn={onRedirectToSignIn} />;
  }

  switch (tab) {
    case 'Server Configuration':
      return (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 w-full">
          {/* SSH Connection Card - Left side taking more space */}
          <div className="lg:col-span-2 w-full lg:flex lg:justify-center lg:items-center"> 
            <SSHConnectionCard
              usernameRef={componentProps.usernameRef}
              ipAddressRef={componentProps.ipAddressRef}
              passwordRef={componentProps.passwordRef}
              keyFileNameRef={componentProps.keyFileNameRef}
              keyFileContentRef={componentProps.keyFileContentRef}
              rememberDetailsRef={componentProps.rememberDetailsRef}
              isConnectedRef={componentProps.isConnectedRef}
              updateUIState={componentProps.updateUIState}
              validateIPv4={componentProps.validateIPv4}
              onConnectionSuccess={componentProps.triggerHistoryRefresh}
            />
          </div>

          {/* Connection History - Right side */}
          <div className="lg:col-span-1">
            <ConnectionHistory 
              onConnectFromHistory={componentProps.onConnectFromHistory}
              onRefresh={componentProps.onRefreshHistory}
            />
          </div>
        </div>
      );
    case 'Application Installation':
      return <AppInstall />;
    case 'Monitoring':
      return <Monitoring />;
    case 'File Explorer':
      return <FileExplorer />;
    case 'Custom Commands':
      return <CustomCommands />;
    default:
      return
  }
}, (prevProps, nextProps) => {
  // Optimize re-rendering based on tab and authentication changes
  return prevProps.tab === nextProps.tab && prevProps.isAuthenticated === nextProps.isAuthenticated;
});

// Authentication required component
const SignInCard = React.memo(({ onRedirectToSignIn }) => (
  <div className="w-full max-w-md bg-black/20 backdrop-blur-xl p-8 rounded-2xl border border-gray-900/50 shadow-2xl">
    <div className="text-center mb-8">
      <LogIn className="h-12 w-12 mx-auto text-white mb-4" />
      <h2 className="text-2xl font-bold text-white mb-2">Authentication Required</h2>
      <p className="text-gray-400 mb-6">Please sign in to access the server management console</p>
    </div>

    <button
      onClick={onRedirectToSignIn}
      className="w-full py-3 bg-gradient-to-r from-white/10 to-white/20 hover:from-white/20 hover:to-white/30 text-white font-medium rounded-xl transition duration-200 cursor-pointer flex items-center justify-center gap-2"
    >
      <LogIn className="h-5 w-5" />
      Sign In
    </button>
  </div>
));

// Loading indicator component
const LoadingSpinner = () => (
  <div className="flex items-center justify-center space-x-2 text-white">
    <Loader className="h-6 w-6 animate-spin" />
    <p className="font-medium">Loading console...</p>
  </div>
);

const Home = ({ isAuthenticated, onRedirectToSignIn, onAuthCheck }) => {
  const [isLoading, setIsLoading] = useState(true);
  const [isDashboardOpen, setIsDashboardOpen] = useState(false);
  const [isInitialized, setIsInitialized] = useState(false);
  const [activeTab, setActiveTab] = useState('Server Configuration');
  const [isVerifying, setIsVerifying] = useState(false);
  
  const dashboardRef = useRef(null);
  const usernameRef = useRef('');
  const ipAddressRef = useRef('');
  const passwordRef = useRef('');
  const keyFileNameRef = useRef('');
  const keyFileContentRef = useRef(null);
  const rememberDetailsRef = useRef(false);
  const isConnectedRef = useRef(false);

  // Expose dashboard state globally for navbar interaction
  useEffect(() => {
    window.dashboardState = {
      setIsDashboardOpen: (state) => {
        setIsDashboardOpen(state);
      },
      getIsDashboardOpen: () => isDashboardOpen
    };
  }, [isDashboardOpen]);

  // Decrypt sensitive data using AES
  const decryptData = encryptedData => {
    try {
      const key = import.meta.env.VITE_SSH_PASSWORD_KEY;
      return CryptoJS.AES.decrypt(encryptedData, key).toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error("Error decrypting data:", error);
      return '';
    }
  };

  // Validate IPv4 address format
  const validateIPv4 = ip => {
    const pattern = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return pattern.test(ip);
  };

  // Update UI based on connection state
  const updateUIState = (isConnected) => {
    // Status text update
    const statusEl = document.querySelector('.connection-status');
    if (statusEl) {
      statusEl.textContent = isConnected ? 'Connected' : 'Not connected';
      statusEl.classList.remove(isConnected ? 'text-gray-400' : 'text-green-400');
      statusEl.classList.add(isConnected ? 'text-green-400' : 'text-gray-400');
    }
    
    // Disable/enable input fields
    document.querySelectorAll('.connection-input').forEach(input => {
      input.disabled = isConnected;
      input.classList.toggle('opacity-70', isConnected);
      input.classList.toggle('cursor-not-allowed', isConnected);
    });
    
    // Update connection card styles
    const cardEl = document.querySelector('.connection-card');
    if (cardEl) {
      cardEl.classList.remove(isConnected ? 'border-gray-900/50' : 'border-green-500/30');
      cardEl.classList.add(isConnected ? 'border-green-500/30' : 'border-gray-900/50');
    }
    
    // Update terminal icon
    const iconEl = document.querySelector('.terminal-icon');
    if (iconEl) {
      iconEl.classList.remove(isConnected ? 'text-white' : 'text-green-400');
      iconEl.classList.add(isConnected ? 'text-green-400' : 'text-white');
    }
    
    // Toggle connect/disconnect buttons
    const connectBtn = document.querySelector('.connect-button');
    const disconnectBtn = document.querySelector('.disconnect-button');
    if (connectBtn) connectBtn.style.display = isConnected ? 'none' : 'block';
    if (disconnectBtn) disconnectBtn.style.display = isConnected ? 'flex' : 'none';
    
    // Persist connection state
    if (isConnected) {
      localStorage.setItem('connectionState', 'connected');
    } else {
      localStorage.removeItem('connectionState');
      localStorage.removeItem('serverOsType');
    }
  };

  // Verify existing SSH connection
  const verifyConnection = async () => {
    // Check for saved connection details
    const savedUsername = localStorage.getItem('serverUsername');
    const savedIpAddress = localStorage.getItem('serverIpAddress');
    const savedConnectionState = localStorage.getItem('connectionState');
    const savedAuthMethod = localStorage.getItem('serverAuthMethod');
    
    if (savedConnectionState === 'connected' && savedUsername && savedIpAddress) {
      setIsVerifying(true);
      
      try {
        const payload = {
          username: savedUsername,
          ipAddress: savedIpAddress,
          authMethod: savedAuthMethod,
          verifyOnly: true
        };
  
        // Attach authentication credentials
        if (savedAuthMethod === 'password') {
          const savedEncryptedPassword = localStorage.getItem('serverPassword');
          if (savedEncryptedPassword) {
            payload.password = savedEncryptedPassword;
          }
        } else if (savedAuthMethod === 'key') {
          const savedKeyFileName = localStorage.getItem('serverKeyFileName');
          const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
          if (savedKeyFileName && savedKeyFileContent) {
            payload.keyFileName = savedKeyFileName;
            payload.keyFileContent = savedKeyFileContent;
          }
        }
  
        const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/verify-connection`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });
  
        const data = await response.json();
        
        if (!data.success) {
          throw new Error(data.message || "Connection verification failed");
        }
        
        // Mark connection as valid
        isConnectedRef.current = true;
        
        if (activeTab === 'Server Configuration') {
          updateUIState(true);
        }
        
        console.log("SSH connection verified successfully");
        
      } catch (error) {
        console.error("Failed to verify connection:", error);
        // Reset connection state
        isConnectedRef.current = false;
        localStorage.removeItem('connectionState');
        
        if (activeTab === 'Server Configuration') {
          updateUIState(false);
        }
        
        toast.error("Server connection lost. Please reconnect.", { 
          icon: '⚠️',
          duration: 3000 
        });
        
        // Redirect to Server Configuration if needed
        if (activeTab !== 'Server Configuration' && activeTab !== 'About') {
          setActiveTab('Server Configuration');
        }
      } finally {
        setIsVerifying(false);
      }
    } else if (isConnectedRef.current && (!savedUsername || !savedIpAddress)) {
      // Handle connection state inconsistency
      isConnectedRef.current = false;
      localStorage.removeItem('connectionState');
      
      if (activeTab === 'Server Configuration') {
        updateUIState(false);
      }
    } else {
      // No connection to verify
      setIsVerifying(false);
    }
    
    // Return connection verification status
    return isConnectedRef.current;
  };

  // Load saved connection details on component mount
  useEffect(() => {
    const loadSavedState = async () => {
      const savedUsername = localStorage.getItem('serverUsername');
      const savedIpAddress = localStorage.getItem('serverIpAddress');
      const savedEncryptedPassword = localStorage.getItem('serverPassword');
      const savedConnectionState = localStorage.getItem('connectionState');
      const savedActiveTab = localStorage.getItem('activeTab');
      const savedAuthMethod = localStorage.getItem('serverAuthMethod');
      const savedKeyFileName = localStorage.getItem('serverKeyFileName');
      const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
      
      // Restore saved credentials
      if (savedUsername || savedIpAddress) {
        usernameRef.current = savedUsername || '';
        ipAddressRef.current = savedIpAddress || '';
        
        if (savedAuthMethod === 'password' && savedEncryptedPassword) {
          passwordRef.current = decryptData(savedEncryptedPassword);
        } else if (savedAuthMethod === 'key' && savedKeyFileName && savedKeyFileContent) {
          keyFileNameRef.current = savedKeyFileName;
          keyFileContentRef.current = savedKeyFileContent;
        }
        
        rememberDetailsRef.current = true;
      }
      
      // Set initial connection state
      if (savedConnectionState === 'connected') {
        isConnectedRef.current = true;
      }
      
      // Restore active tab
      if (savedActiveTab) {
        setActiveTab(savedActiveTab);
      }
      
      setIsInitialized(true);
      
      // Verify connection on initial load
      await verifyConnection();
    };
    
    loadSavedState();
  }, []);

  // Apply UI state after component initialization
  useEffect(() => {
    if (isInitialized && !isLoading && !isVerifying && activeTab === 'Server Configuration') {
      // Populate form fields based on saved auth method
      const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
      
      if (authMethod === 'password') {
        ['username', 'ipAddress', 'password', 'rememberDetails', 'auth-method-password'].forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            if (id === 'username') el.value = usernameRef.current;
            else if (id === 'ipAddress') el.value = ipAddressRef.current;
            else if (id === 'password' && passwordRef.current) el.value = passwordRef.current;
            else if (id === 'rememberDetails') el.checked = rememberDetailsRef.current;
            else if (id === 'auth-method-password') el.checked = true;
          }
        });
      } else if (authMethod === 'key') {
        ['username', 'ipAddress', 'rememberDetails', 'auth-method-key'].forEach(id => {
          const el = document.getElementById(id);
          if (el) {
            if (id === 'username') el.value = usernameRef.current;
            else if (id === 'ipAddress') el.value = ipAddressRef.current;
            else if (id === 'rememberDetails') el.checked = rememberDetailsRef.current;
            else if (id === 'auth-method-key') el.checked = true;
          }
        });
      }
      
      // Apply connection UI state if needed
      if (isConnectedRef.current) {
        updateUIState(true);
      }
    }
  }, [isInitialized, isLoading, isVerifying, activeTab]);

  // Initial loading timer
  useEffect(() => {
    setIsLoading(true);
    const timer = setTimeout(() => setIsLoading(false), 500);
    return () => clearTimeout(timer);
  }, [isAuthenticated]);

  // Save active tab to localStorage
  useEffect(() => {
    localStorage.setItem('activeTab', activeTab);
  }, [activeTab]);

  // Dashboard click outside handler
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (!window.matchMedia("(min-width: 768px)").matches && isDashboardOpen &&
          dashboardRef.current && !dashboardRef.current.contains(event.target)) {
        setIsDashboardOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isDashboardOpen]);

  // Enhanced sidepanel action with authentication check
  const handleSidePanelAction = async (label) => {
    if (activeTab !== label) {
      setIsLoading(true);
      
      // About tab is accessible without authentication
      if (label === 'About') {
        setActiveTab(label);
        setIsLoading(false);
        setIsDashboardOpen(false);
        return;
      }
      
      // Perform server-side authentication validation on every tab change
      if (!isAuthenticated) {
        setIsLoading(false);
        onRedirectToSignIn();
        return;
      }
      
      // Call the parent authentication check to perform API validation
      const authCheckResult = await onAuthCheck();
      
      // If auth check fails, don't change tab and redirect to sign in
      if (!authCheckResult) {
        setIsLoading(false);
        onRedirectToSignIn();
        return;
      }
      
      // Verify SSH connection on every tab change
      const connectionVerified = await verifyConnection();
      
      // Update active tab
      setActiveTab(label);
      
      // If we're trying to access a tab other than Server Configuration
      // and the connection isn't verified, redirect to the Server Configuration tab
      if (label !== 'Server Configuration' && !connectionVerified) {
        toast.error("Please configure and connect to a server first", {
          icon: '⚠️',
          duration: 3000
        });
        setActiveTab('Server Configuration');
      }
      
      setIsLoading(false);
    }
    
    setIsDashboardOpen(false);
  };

  // Ref to store connection history refresh function
  const refreshHistoryRef = useRef(null)

  // Handle connection from history
  const handleConnectFromHistory = useCallback((connection) => {
    // Update connection state when connecting from history
    isConnectedRef.current = true
    if (activeTab === 'Server Configuration') {
      updateUIState(true)
    }
    // Update refs with connection details
    usernameRef.current = connection.server_username
    ipAddressRef.current = connection.server_ip
  }, [activeTab, updateUIState]);

  // Callback to refresh connection history
  const handleRefreshHistory = useCallback((refreshFn) => {
    refreshHistoryRef.current = refreshFn
  }, []);

  // Function to trigger history refresh (can be called after successful connection)
  const triggerHistoryRefresh = useCallback(() => {
    if (refreshHistoryRef.current) {
      refreshHistoryRef.current()
    }
  }, []);

  // Memoize component props to prevent unnecessary re-renders
  const componentProps = useMemo(() => ({
    usernameRef,
    ipAddressRef,
    passwordRef,
    keyFileNameRef,
    keyFileContentRef,
    rememberDetailsRef,
    isConnectedRef,
    updateUIState,
    validateIPv4,
    onConnectFromHistory: handleConnectFromHistory,
    onRefreshHistory: handleRefreshHistory,
    triggerHistoryRefresh: triggerHistoryRefresh
  }), [handleConnectFromHistory, handleRefreshHistory, triggerHistoryRefresh]);

  // Navigation items - added About with InfoIcon
  const navItems = [
    { icon: Server, label: 'Server Configuration' },
    { icon: Package, label: 'Application Installation' },
    { icon: Cpu, label: 'Monitoring' },
    { icon: FolderOpen, label: 'File Explorer' },
    { icon: Terminal, label: 'Custom Commands' },
  ];

  return (
    <div className="min-h-svh pt-16 bg-gradient-to-br from-black via-black/90 to-black overflow-hidden flex">
      <ToastContainer />

      {/* Backdrop blur when sidebar is open on mobile */}
      {isDashboardOpen && !window.matchMedia("(min-width: 768px)").matches && (
        <div 
          className="fixed inset-0 bg-black/30 backdrop-blur-sm z-30"
          onClick={() => setIsDashboardOpen(false)}
        />
      )}

      {/* Dashboard Panel */}
      <div className="flex-none">
        <div
          ref={dashboardRef}
          className={`fixed z-40 top-16 left-0 bottom-0 w-[300px] bg-black/70 backdrop-blur-xl border-r border-gray-900/50 p-6 transform transition-transform duration-300 ease-in-out ${
            isDashboardOpen ? 'translate-x-0' : '-translate-x-full'
          } md:translate-x-0`}
        >
          <div className="space-y-2 select-none mb-8">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold text-white">Dashboard</h2>
              {/* Close button - only visible on mobile */}
              <button 
                onClick={() => setIsDashboardOpen(false)}
                className="text-gray-400 cursor-pointer hover:text-white p-1 rounded-lg bg-white/5 md:hidden"
                aria-label="Close dashboard"
              >
                <X className="size-6" />
              </button>
            </div>
          </div>

          <nav className="space-y-2">
            {navItems.map(({ icon: Icon, label }) => (
              <button
                key={label}
                onClick={() => handleSidePanelAction(label)}
                className={`w-full flex items-center cursor-pointer select-none gap-3 py-2 px-3 ${activeTab === label ? 'bg-white/10 text-white' : 'text-gray-400'} hover:bg-white/10 hover:text-white rounded-xl transition-all duration-200`}
              >
                <Icon className="h-5 w-5" />
                <span className="text-sm">{label}</span>
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Main Area */}
      <div className="flex-1 md:ml-[300px] overflow-y-auto h-[calc(100vh-4rem)]">
      <CustomScrollbar>
        <div className="p-6">
          {/* Display the current tab name */}
          <div className="mb-6 inline-block">
            <h1 className="text-2xl font-bold text-white">{activeTab}</h1>
            <div className="h-1 w-full bg-gradient-to-r from-white/80 to-black/20 rounded-full"></div>
          </div>
          
          {/* Content area */}
          <div className="flex items-center justify-center h-[calc(100vh-12rem)]">
            {isLoading || isVerifying ? (
              <LoadingSpinner />
            ) : (
              <MemoizedTabContent 
                tab={activeTab} 
                isAuthenticated={isAuthenticated} 
                onRedirectToSignIn={onRedirectToSignIn}
                componentProps={componentProps}
              />
            )}
          </div>
        </div>
      </CustomScrollbar>
      </div>
    </div>
  )};

export default Home;
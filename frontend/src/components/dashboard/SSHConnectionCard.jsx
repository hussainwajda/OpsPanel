import React, { useState, useRef, useEffect } from 'react';
import { 
  Server, TerminalSquare, User, Lock, Eye, EyeOff, X, Key, FileText, Info
} from 'lucide-react';
import toast from 'react-hot-toast';
import CryptoJS from 'crypto-js';

const SSHConnectionCard = ({
  usernameRef, 
  ipAddressRef, 
  passwordRef,
  keyFileNameRef,
  keyFileContentRef,
  rememberDetailsRef,
  isConnectedRef,
  updateUIState,
  validateIPv4
}) => {
  // State for password visibility and authentication method
  const [showPassword, setShowPassword] = useState(false);
  const [authMethod, setAuthMethod] = useState('password');
  const [keyFileName, setKeyFileName] = useState('');
  const keyFileRef = useRef(null);

  // Encrypt password securely
  const encryptPassword = password => {
    try {
      const key = import.meta.env.VITE_SSH_PASSWORD_KEY;
      return CryptoJS.AES.encrypt(password, key).toString();
    } catch (error) {
      console.error("Error encrypting password:", error);
      return null;
    }
  };

  // Encrypt SSH key file content
  const encryptKeyFile = (content) => {
    try {
      const key = import.meta.env.VITE_SSH_PASSWORD_KEY;
      return CryptoJS.AES.encrypt(content, key).toString();
    } catch (error) {
      console.error("Error encrypting key file:", error);
      return null;
    }
  };

  // Restore saved authentication method
  useEffect(() => {
    const savedAuthMethod = localStorage.getItem('serverAuthMethod');
    const savedKeyFileName = localStorage.getItem('serverKeyFileName');
    
    // Set authentication method from localStorage
    if (savedAuthMethod === 'key') {
      setAuthMethod('key');
      if (savedKeyFileName) {
        setKeyFileName(savedKeyFileName);
      }
      
      // Restore key file content
      const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
      if (savedKeyFileContent) {
        keyFileContentRef.current = savedKeyFileContent;
      }
    } else {
      setAuthMethod('password');
    }
  }, [keyFileContentRef]);

  // Handle key file selection
  const handleKeyFileChange = (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate key file extension
    const validExtensions = ['.pem', '.ppk'];
    const fileExtension = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();
    
    if (!validExtensions.includes(fileExtension)) {
      toast.error("Please select a valid .pem or .ppk key file", { icon: '⚠️' });
      e.target.value = '';
      return;
    }

    setKeyFileName(file.name);
    
    // Read file content
    const reader = new FileReader();
    reader.onload = (event) => {
      keyFileContentRef.current = event.target.result;
    };
    reader.readAsText(file);
  };

  // Establish server connection
  const handleConnect = () => {
    if (isConnectedRef.current) return;
  
    const username = usernameRef.current;
    const ipAddress = ipAddressRef.current;
  
    // Validate connection inputs
    if (!username || !ipAddress) {
      toast.error("Please fill in username and IP address", { icon: '⚠️' });
      return;
    }
  
    // Validate IP address format
    if (!validateIPv4(ipAddress)) {
      toast.error("Please enter a valid IPv4 address", { icon: '⚠️' });
      return;
    }
  
    // Validate authentication method inputs
    if (authMethod === 'password' && !passwordRef.current) {
      toast.error("Please enter a password", { icon: '⚠️' });
      return;
    }
  
    if (authMethod === 'key' && !keyFileContentRef.current) {
      toast.error("Please select a key file", { icon: '⚠️' });
      return;
    }
  
    // Persist connection details
    localStorage.setItem('serverUsername', username);
    localStorage.setItem('serverIpAddress', ipAddress);
    localStorage.setItem('serverAuthMethod', authMethod);
    
    if (authMethod === 'password') {
      const encryptedPassword = encryptPassword(passwordRef.current);
      if (encryptedPassword) {
        localStorage.setItem('serverPassword', encryptedPassword);
      }
      // Clear key file data
      localStorage.removeItem('serverKeyFileName');
      localStorage.removeItem('serverKeyFileContent');
    } else {
      // Save key file data
      localStorage.setItem('serverKeyFileName', keyFileName);
      const encryptedKeyContent = encryptKeyFile(keyFileContentRef.current);
      if (encryptedKeyContent) {
        localStorage.setItem('serverKeyFileContent', encryptedKeyContent);
      }
      // Clear password
      localStorage.removeItem('serverPassword');
    }
  
    // Establish server connection
    const connectToServer = async () => {
      const payload = {
        username,
        ipAddress,
        authMethod
      };
  
      // Add authentication credentials
      if (authMethod === 'password') {
        payload.password = encryptPassword(passwordRef.current);
      } else {
        payload.keyFileContent = encryptKeyFile(keyFileContentRef.current);
        payload.keyFileName = keyFileName;
      }
  
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/connect`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });
  
      const data = await response.json();
      
      if (!data.success) {
        throw new Error(data.message);
      }
      
      // Store server OS information
      localStorage.setItem('serverOsType', data.osType);
      
      // Update connection state
      localStorage.setItem('connectionState', 'connected');
      
      return data;
    };
  
    // Handle connection with toast notifications
    toast.promise(
      connectToServer(),
      {
        loading: 'Connecting to server...',
        success: (data) => {
          isConnectedRef.current = true;
          updateUIState(true);
          return <b>Connected to {data.osType} server!</b>;
        },
        error: (err) => <b>{err.message || 'Failed to connect to server'}</b>,
      },
      { 
        success: { duration: 3000 },
        error: { duration: 3000 }
      }
    );
  };

  // Disconnect from server
  const handleDisconnect = () => {
    isConnectedRef.current = false;
    updateUIState(false);
    toast.success('Disconnected!');
  };

  // Use saved connection state for initial rendering
  const initialConnected = isConnectedRef.current;
  
  return (
    <div className={`w-full select-none max-w-sm bg-black/20 backdrop-blur-xl p-6 rounded-2xl border ${initialConnected ? 'border-green-500/30' : 'border-gray-900/50'} shadow-2xl connection-card`}>
      <div className="flex justify-between items-center mb-5">
        <div className="flex items-center">
          <TerminalSquare className={`h-7 w-7 ${initialConnected ? 'text-green-400' : 'text-white'} mr-3 terminal-icon`} />
          <div>
            <h2 className="text-lg font-bold text-white">Server Connection</h2>
            <p className={`text-xs ${initialConnected ? 'text-green-400' : 'text-gray-400'} connection-status`}>
              {initialConnected ? 'Connected' : 'Not connected'}
            </p>
          </div>
        </div>
      </div>

      <form onSubmit={(e) => e.preventDefault()} className="space-y-3">
        {/* Username input */}
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <User className="h-4 w-4 text-gray-400" />
          </div>
          <input
            id="username"
            type="text"
            defaultValue={usernameRef.current}
            onChange={(e) => { usernameRef.current = e.target.value; }}
            placeholder="Username"
            disabled={initialConnected}
            className={`block w-full pl-9 pr-3 py-2 rounded-lg bg-black/20 border-none text-white placeholder-gray-400 ring-1 ${initialConnected ? 'ring-green-500/30 opacity-70 cursor-not-allowed' : 'ring-white/20'} focus:ring-2 focus:ring-white/20 transition-all duration-200 outline-none text-sm connection-input`}
          />
        </div>
        
        {/* IP Address input */}
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Server className="h-4 w-4 text-gray-400" />
          </div>
          <input
            id="ipAddress"
            type="text"
            defaultValue={ipAddressRef.current}
            onChange={(e) => {
              // Sanitize IP input
              const value = e.target.value.replace(/[^\d.]/g, '');
              e.target.value = value;
              ipAddressRef.current = value;
            }}
            onBlur={(e) => {
              if (e.target.value && !validateIPv4(e.target.value)) {
                e.target.classList.add('ring-red-500');
              } else {
                e.target.classList.remove('ring-red-500');
              }
            }}
            placeholder="IP Address (e.g. 192.168.1.1)"
            disabled={initialConnected}
            className={`block w-full pl-9 pr-3 py-2 rounded-lg bg-black/20 border-none text-white placeholder-gray-400 ring-1 ${initialConnected ? 'ring-green-500/30 opacity-70 cursor-not-allowed' : 'ring-white/20'} focus:ring-2 focus:ring-white/20 transition-all duration-200 outline-none text-sm connection-input`}
          />
        </div>

        {/* Authentication Method Selector */}
        <div>
          {/* Password Authentication */}
          <div className={`relative mb-1 ${authMethod === 'password' ? 'opacity-100' : 'opacity-50'}`}>
            <div className="flex items-center mb-2">
              <input
                id="auth-method-password"
                type="radio"
                name="auth-method"
                checked={authMethod === 'password'}
                onChange={() => setAuthMethod('password')}
                disabled={initialConnected}
                className={`h-4 w-4 text-indigo-500 rounded cursor-pointer connection-input ${initialConnected ? 'opacity-70 cursor-not-allowed' : ''}`}
              />
              <label htmlFor="auth-method-password" className={`ml-2 text-sm text-white flex items-center ${initialConnected ? 'cursor-not-allowed' : 'cursor-pointer'}`}>
                <Lock className="h-3 w-3 mr-1 text-gray-400" />
                Password
              </label>
            </div>

            {/* Password Input */}
            {(authMethod === 'password' || (initialConnected && localStorage.getItem('serverAuthMethod') === 'password')) && (
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-4 w-4 text-gray-400" />
                </div>
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  defaultValue={passwordRef.current}
                  onChange={(e) => { passwordRef.current = e.target.value; }}
                  placeholder="Password"
                  disabled={initialConnected}
                  className={`block w-full pl-9 pr-10 py-2 rounded-lg bg-black/20 border-none text-white placeholder-gray-400 ring-1 ${initialConnected ? 'ring-green-500/30 opacity-70 cursor-not-allowed' : 'ring-white/20'} focus:ring-2 focus:ring-white/20 transition-all duration-200 outline-none text-sm connection-input`}
                />
                <button 
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute cursor-pointer inset-y-0 right-0 pr-3 flex items-center text-gray-400 hover:text-white"
                  disabled={initialConnected}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            )}
          </div>
          
          {/* Divider */}
          <div className="relative flex items-center my-4">
            <div className="flex-grow border-t border-gray-700"></div>
            <span className="flex-shrink mx-3 text-xs text-gray-400">or</span>
            <div className="flex-grow border-t border-gray-700"></div>
          </div>
          
          {/* Key File Authentication */}
          <div className={`relative ${authMethod === 'key' ? 'opacity-100' : 'opacity-50'}`}>
            <div className="flex items-center mb-2">
              <input
                id="auth-method-key"
                type="radio"
                name="auth-method"
                checked={authMethod === 'key'}
                onChange={() => setAuthMethod('key')}
                disabled={initialConnected}
                className={`h-4 w-4 text-indigo-500 rounded cursor-pointer connection-input ${initialConnected ? 'opacity-70 cursor-not-allowed' : ''}`}
              />
              <label htmlFor="auth-method-key" className={`ml-2 text-sm text-white flex items-center ${initialConnected ? 'cursor-not-allowed' : 'cursor-pointer'}`}>
                <Key className="h-3 w-3 mr-1 text-gray-400" />
                SSH Key (.pem, .ppk)
              </label>
            </div>

            {/* Key File Input */}
            {(authMethod === 'key' || (initialConnected && localStorage.getItem('serverAuthMethod') === 'key')) && (
              <div className="relative">
                <label 
                  htmlFor="key-file-input" 
                  className={`block w-full py-2 px-3 rounded-lg bg-black/20 border border-dashed border-gray-600 text-white text-sm transition-all duration-200 ${initialConnected ? 'opacity-70 cursor-not-allowed' : 'cursor-pointer hover:border-white/30'}`}
                >
                  <div className="flex items-center">
                    <FileText className="h-4 w-4 text-gray-400 mr-2" />
                    {keyFileName ? keyFileName : "Select key file..."}
                  </div>
                </label>
                <input
                  id="key-file-input"
                  ref={keyFileRef}
                  type="file"
                  accept=".pem,.ppk"
                  onChange={handleKeyFileChange}
                  disabled={initialConnected}
                  className="hidden connection-input"
                />
              </div>
            )}
          </div>
        </div>

        {/* Security note */}
        <div className="flex items-center text-xs text-gray-400 mt-4">
          <Info className="h-3 w-3 mr-2 flex-shrink-0" />
          <p>Your connection details are securely stored in your browser for convenience. No data is sent to external servers.</p>
        </div>

        <div>
          {/* Connect button */}
          <button
            onClick={handleConnect}
            className="w-full py-2 bg-gradient-to-r from-white/10 to-white/20 hover:from-white/20 hover:to-white/30 text-white font-medium rounded-lg transition duration-200 cursor-pointer text-sm connect-button"
            style={{ display: initialConnected ? 'none' : 'block' }}
          >
            Connect
          </button>

          {/* Disconnect button */}
          <button
            onClick={handleDisconnect}
            className="w-full py-2 bg-red-500/50 hover:bg-red-500/70 text-white font-medium rounded-lg transition duration-200 cursor-pointer text-sm flex items-center justify-center disconnect-button"
            style={{ display: initialConnected ? 'flex' : 'none' }}
          >
            <X className="h-4 w-4 mr-2" />
            Disconnect
          </button>
        </div>
      </form>
    </div>
  );
};

export default SSHConnectionCard;
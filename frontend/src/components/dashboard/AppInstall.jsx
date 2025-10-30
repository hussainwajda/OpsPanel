import React, { useState, useEffect } from 'react';
import { Package, Shield, CheckCircle, Loader } from 'lucide-react';
import toast from 'react-hot-toast';
import CryptoJS from 'crypto-js';

const AppInstall = () => {
  // Centralized state for application management
  const [selectedApplications, setSelectedApplications] = useState({
    docker: { selected: false, logoUrl: 'docker.png', installed: false, version: '' },
    caddy: { selected: false, logoUrl: 'caddy.png', installed: false, version: '' },
    nginx: { selected: false, logoUrl: 'nginx.png', installed: false, version: '' },
    apache2: { selected: false, logoUrl: 'apache2.png', installed: false, version: '' },
    awsCli: { selected: false, logoUrl: 'aws-cli.png', installed: false, version: '' },
  });

  // Tracking loading and installation check states
  const [loading, setLoading] = useState(true);
  const [checkingInstalled, setCheckingInstalled] = useState(true);

  // Secure decryption utility for sensitive data
  const decryptData = (encryptedData) => {
    try {
      const key = import.meta.env.VITE_SSH_PASSWORD_KEY;
      return CryptoJS.AES.decrypt(encryptedData, key).toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error("Decryption failed", error);
      return null;
    }
  };

  // Fetch and verify installed applications on component mount
  useEffect(() => {
    const checkInstalledApplications = async () => {
      setCheckingInstalled(true);
      try {
        // Validate server connection prerequisites
        const username = localStorage.getItem('serverUsername');
        const ipAddress = localStorage.getItem('serverIpAddress');
        const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
        
        if (!username || !ipAddress) {
          toast.error('Configure server connection first');
          setCheckingInstalled(false);
          setLoading(false);
          return;
        }
    
        // Ensure active server connection
        const isConnected = localStorage.getItem('connectionState') === 'connected';
        if (!isConnected) {
          toast.error('Connect to a server first');
          setCheckingInstalled(false);
          setLoading(false);
          return;
        }

        // Prepare authentication payload
        const payload = {
          username,
          ipAddress,
          authMethod
        };

        // Handle different authentication methods
        if (authMethod === 'password') {
          const savedEncryptedPassword = localStorage.getItem('serverPassword');
          if (!savedEncryptedPassword) {
            throw new Error('No password found');
          }
          const decryptedPassword = decryptData(savedEncryptedPassword);
          payload.password = CryptoJS.AES.encrypt(decryptedPassword, import.meta.env.VITE_SSH_PASSWORD_KEY).toString();
        } else {
          // Key-based authentication handling
          const savedKeyFileName = localStorage.getItem('serverKeyFileName');
          const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
          if (!savedKeyFileName || !savedKeyFileContent) {
            throw new Error('No key file found');
          }
          payload.keyFileName = savedKeyFileName;
          payload.keyFileContent = savedKeyFileContent;
        }

        // Send installation check request
        const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/check-installed`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(payload),
        });

        const data = await response.json();

        if (!data.success) {
          throw new Error(data.message || 'Installation check failed');
        }

        // Update application installation states
        setSelectedApplications(prev => {
          const updated = { ...prev };
          Object.keys(data.installed).forEach(app => {
            if (updated[app]) {
              updated[app] = {
                ...updated[app],
                installed: data.installed[app].installed,
                version: data.installed[app].version
              };
            }
          });
          return updated;
        });
      } catch (error) {
        console.error('Installation check error', error);
        toast.error(error.message || 'Failed to check installations');
      } finally {
        setCheckingInstalled(false);
        setLoading(false);
      }
    };

    checkInstalledApplications();
  }, []);

  // Bulk application installation handler
  const handleInstallApplications = async () => {
    // Validate application selection
    const selectedApps = Object.keys(selectedApplications)
      .filter(app => selectedApplications[app].selected);
    
    if (selectedApps.length === 0) {
      toast.error('Select at least one application', { 
        icon: '⚠️',
        duration: 3000 
      });
      return;
    }

    // Validate server connection details
    const username = localStorage.getItem('serverUsername');
    const ipAddress = localStorage.getItem('serverIpAddress');
    const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
    
    if (!username || !ipAddress) {
      toast.error('Configure server connection first', {
        duration: 3000
      });
      return;
    }

    // Verify active server connection
    const isConnected = localStorage.getItem('connectionState') === 'connected';
    if (!isConnected) {
      toast.error('Connect to a server first', {
        duration: 3000
      });
      return;
    }

    // Persistent loading indicator
    const loadingToastId = toast.loading('Installing applications...', {
      duration: Infinity
    });

    try {
      const payload = {
        username,
        ipAddress,
        authMethod,
        applications: selectedApps
      };

      // Authentication payload preparation
      if (authMethod === 'password') {
        const savedEncryptedPassword = localStorage.getItem('serverPassword');
        if (!savedEncryptedPassword) {
          toast.dismiss(loadingToastId);
          toast.error('No password found', {
            duration: 3000
          });
          return;
        }
        const decryptedPassword = decryptData(savedEncryptedPassword);
        payload.password = CryptoJS.AES.encrypt(decryptedPassword, import.meta.env.VITE_SSH_PASSWORD_KEY).toString();
      } else {
        // Key file authentication
        const savedKeyFileName = localStorage.getItem('serverKeyFileName');
        const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
        if (!savedKeyFileName || !savedKeyFileContent) {
          toast.dismiss(loadingToastId);
          toast.error('No key file found', {
            duration: 3000
          });
          return;
        }
        payload.keyFileName = savedKeyFileName;
        payload.keyFileContent = savedKeyFileContent;
      }

      // Send installation request
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/install`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Installation failed');
      }
      
      // Update application states based on installation results
      data.results.forEach(result => {
        setSelectedApplications(prev => ({
          ...prev,
          [result.application]: {
            ...prev[result.application],
            installed: result.success,
            selected: false,
            version: result.success ? 'Just installed' : prev[result.application].version
          }
        }));
      });
      
      // Categorize installation results
      const successResults = data.results.filter(r => r.success).map(r => r.application);
      const failedResults = data.results.filter(r => !r.success).map(r => `${r.application}: ${r.message}`);
      
      toast.dismiss(loadingToastId);

      // Detailed installation result notification
      if (successResults.length > 0) {
        toast.success(
          <div>
            <div className="font-bold mb-1">Successfully installed:</div>
            <ul className="list-disc pl-4">
              {successResults.map(app => (
                <li key={app}>{app}</li>
              ))}
            </ul>
            {failedResults.length > 0 && (
              <>
                <div className="font-bold mt-2 mb-1">Failed to install:</div>
                <ul className="list-disc pl-4">
                  {failedResults.map((error, i) => (
                    <li key={i} className="text-sm">{error}</li>
                  ))}
                </ul>
              </>
            )}
          </div>,
          { 
            duration: 5000,
            position: 'top-center'
          }
        );
      } else {
        toast.error(
          <div>
            <div className="font-bold mb-1">Installation failed for all applications:</div>
            <ul className="list-disc pl-4">
              {failedResults.map((error, i) => (
                <li key={i} className="text-sm">{error}</li>
              ))}
            </ul>
          </div>,
          { 
            duration: 5000,
            position: 'top-center'
          }
        );
      }
      
    } catch (error) {
      // Handle and log installation errors
      console.error('Installation error:', error);
      
      // Dismiss loading toast
      toast.dismiss(loadingToastId);
      
      // Show error notification
      toast.error(`Installation failed: ${error.message}`, {
        duration: 3000,
        position: 'top-center'
      });
    }
  };

  // Predefined application configurations
  const applications = [
    { id: 'docker', name: 'Docker', placeholderColor: 'bg-blue-100' },
    { id: 'caddy', name: 'Caddy', placeholderColor: 'bg-green-100' },
    { id: 'nginx', name: 'Nginx', placeholderColor: 'bg-green-200' },
    { id: 'apache2', name: 'Apache2', placeholderColor: 'bg-red-100' },
    { id: 'awsCli', name: 'AWS CLI', placeholderColor: 'bg-green-100' },
  ];

  // Toggle application selection state
  const toggleApplicationSelection = (id) => {
    // Prevent selecting already installed applications
    if (selectedApplications[id].installed) {
      toast.error(`${id} is already installed`);
      return;
    }

    setSelectedApplications(prev => ({
      ...prev,
      [id]: {
        ...prev[id],
        selected: !prev[id].selected
      }
    }));
  };

  // Initial loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center space-x-2 text-white">
        <Loader className="h-6 w-6 animate-spin" />
        <p className="font-medium">Loading console...</p>
      </div>
    );
  }

  return (
    <div className="relative h-full w-full">
      <div className="flex justify-between items-center mb-4">
        <span className="text-white text-lg">Select apps to install</span>
        <button
          onClick={handleInstallApplications}
          className="py-2 px-4 bg-gradient-to-r from-white/10 to-white/20 hover:from-white/20 hover:to-white/30 text-white font-medium rounded-lg transition duration-200 cursor-pointer"
        >
          Install
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 pb-4">
        {applications.map(({ id, name, placeholderColor }) => (
          <div 
            key={id}
            onClick={() => toggleApplicationSelection(id)}
            className={`
              relative cursor-pointer rounded-xl p-3 transition-all duration-300 
              flex items-center space-x-4
              ${selectedApplications[id].installed 
                ? 'ring-1 ring-green-500/50 bg-green-900/20' 
                : selectedApplications[id].selected 
                  ? 'ring-1 ring-indigo-500/50' 
                  : 'hover:bg-white/5'}
              border border-white/10 
            `}
          >
            {/* Installed status badge */}
            {selectedApplications[id].installed && (
              <div className="absolute -top-2 -right-2 bg-green-600 text-white text-xs px-2 py-1 rounded-full flex items-center">
                <CheckCircle className="w-3 h-3 mr-1" />
                Installed
              </div>
            )}
            
            {/* Application logo container */}
            <div 
              className={`
                w-16 h-16 rounded-xl flex items-center justify-center 
                ${placeholderColor}
              `}
            >
              {selectedApplications[id].logoUrl ? (
                <img 
                  src={selectedApplications[id].logoUrl} 
                  alt={`${name} logo`} 
                  className="w-full h-full rounded-xl object-contain"
                />
              ) : (
                <span className="text-gray-600 text-sm">Logo</span>
              )}
            </div>

            {/* Application details */}
            <div className="flex flex-col">
              <span className="text-white text-sm">{name}</span>
              {selectedApplications[id].installed && selectedApplications[id].version && (
                <span className="text-gray-400 text-xs mt-1 max-w-[150px] truncate">
                  {selectedApplications[id].version}
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default AppInstall;
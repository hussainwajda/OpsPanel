import React, { useState, useEffect, useRef } from 'react';
import { 
  Cpu, 
  Server, 
  Activity, 
  List, 
  RefreshCw,
  Clock,
  Pause,
  Play,
  ArrowUp,
  ArrowDown
} from 'lucide-react';
import toast from 'react-hot-toast';
import CryptoJS from 'crypto-js';
import { Loader } from 'lucide-react';
import CustomScrollbar from './../CustomScrollbar.jsx';

// Simple loading indicator
const LoadingSpinner = () => (
  <div className="flex items-center justify-center space-x-2 text-white">
    <Loader className="h-6 w-6 animate-spin" />
    <p className="font-medium">Loading console...</p>
  </div>
);

const Monitoring = () => {
  // Component state management
  const [processInfo, setProcessInfo] = useState({
    cpuInfo: null,
    memoryInfo: null,
    processes: [],
    systemLoad: null
  });

  // Connection and loading states
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [isInitialLoad, setIsInitialLoad] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Interval management
  const [intervalOption, setIntervalOption] = useState('none');
  const [isIntervalRunning, setIsIntervalRunning] = useState(false);
  const [isIntervalDropdownOpen, setIsIntervalDropdownOpen] = useState(false);
  const intervalRef = useRef(null);

  // Sorting configuration
  const [sortField, setSortField] = useState('memory');
  const [sortDirection, setSortDirection] = useState('desc');

  // Initialize component settings from localStorage
  useEffect(() => {
    // Restore interval settings
    const savedInterval = localStorage.getItem('monitorRefreshInterval');
    if (savedInterval && savedInterval !== 'none') {
      setIntervalOption(savedInterval);
      
      // Restore freeze state
      const isFreezeSaved = localStorage.getItem('monitorIntervalFrozen');
      const shouldRun = isFreezeSaved === null || isFreezeSaved === 'false';
      setIsIntervalRunning(shouldRun);
    }

    // Restore sort preferences
    const savedSortField = localStorage.getItem('monitorSortField');
    const savedSortDirection = localStorage.getItem('monitorSortDirection');

    if (savedSortField) {
      setSortField(savedSortField);
    }
    if (savedSortDirection) {
      setSortDirection(savedSortDirection);
    }

    fetchMonitoringData();
  }, []);

  // Securely decrypt sensitive data
  const decryptData = (encryptedData) => {
    try {
      const key = import.meta.env.VITE_SSH_PASSWORD_KEY;
      return CryptoJS.AES.decrypt(encryptedData, key).toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error("Error decrypting data:", error);
      return null;
    }
  };

  // Retrieve monitoring data from server
  const fetchMonitoringData = async () => {
    // Sync sort settings from localStorage
    const currentSortField = localStorage.getItem('monitorSortField') || 'memory';
    const currentSortDirection = localStorage.getItem('monitorSortDirection') || 'desc';
    
    // Update state to match localStorage
    if (currentSortField !== sortField) {
      setSortField(currentSortField);
    }
    if (currentSortDirection !== sortDirection) {
      setSortDirection(currentSortDirection);
    }

    // Retrieve stored connection details
    const savedUsername = localStorage.getItem('serverUsername');
    const savedIpAddress = localStorage.getItem('serverIpAddress');
    const savedAuthMethod = localStorage.getItem('serverAuthMethod') || 'password';
    const savedEncryptedPassword = localStorage.getItem('serverPassword');
    const savedKeyFileName = localStorage.getItem('serverKeyFileName');
    const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');

    // Validate stored connection details
    if (!savedUsername || !savedIpAddress) {
      toast.error('No saved server connection found. Please connect first.');
      setIsLoading(false);
      setIsInitialLoad(false);
      return;
    }

    // Validate authentication details
    if (savedAuthMethod === 'password' && !savedEncryptedPassword) {
      toast.error('No saved password found. Please reconnect.');
      setIsLoading(false);
      setIsInitialLoad(false);
      return;
    }

    if (savedAuthMethod === 'key' && (!savedKeyFileName || !savedKeyFileContent)) {
      toast.error('No saved key file found. Please reconnect.');
      setIsLoading(false);
      setIsInitialLoad(false);
      return;
    }

    // Set loading states
    if (isInitialLoad) {
      setIsLoading(true);
    } else {
      setIsRefreshing(true);
    }

    try {
      // Prepare authentication payload
      const payload = {
        username: savedUsername,
        ipAddress: savedIpAddress,
        authMethod: savedAuthMethod
      };

      if (savedAuthMethod === 'password') {
        const decryptedPassword = decryptData(savedEncryptedPassword);
        if (!decryptedPassword) {
          throw new Error('Failed to decrypt saved password');
        }
        payload.password = CryptoJS.AES.encrypt(decryptedPassword, import.meta.env.VITE_SSH_PASSWORD_KEY).toString();
      } else {
        // Key file authentication
        payload.keyFileName = savedKeyFileName;
        payload.keyFileContent = savedKeyFileContent;
      }

      // Send monitoring request
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/monitor`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Failed to fetch monitoring data');
      }

      // Update process information with sorted data
      setProcessInfo({
        cpuInfo: data.cpuInfo,
        memoryInfo: data.memoryInfo,
        processes: sortProcesses(data.processes, currentSortField, currentSortDirection),
        systemLoad: data.systemLoad
      });

      setIsConnected(true);
      toast.success('Monitoring data retrieved successfully');
      
      // Mark initial load as complete
      if (isInitialLoad) {
        setIsInitialLoad(false);
      }
    } catch (error) {
      toast.error(error.message || 'Failed to retrieve monitoring data');
      setIsConnected(false);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  // Sort processes based on selected field and direction
  const sortProcesses = (processes, field, direction) => {
    const sortedProcesses = [...processes];
    
    return sortedProcesses.sort((a, b) => {
      let aValue, bValue;
      
      // Handle different field types for sorting
      switch (field) {
        case 'pid':
          aValue = parseInt(a.pid);
          bValue = parseInt(b.pid);
          break;
        case 'cpu':
          aValue = parseFloat(a.cpu);
          bValue = parseFloat(b.cpu);
          break;
        case 'memory':
          aValue = parseFloat(a.memory);
          bValue = parseFloat(b.memory);
          break;
        case 'user':
          aValue = a.user.toLowerCase();
          bValue = b.user.toLowerCase();
          break;
        default:
          return 0;
      }
      
      // Determine sort order
      if (direction === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });
  };

  // Handle column sorting
  const handleSort = (field) => {
    let newDirection;
    
    // Toggle sort direction or set default
    if (field === sortField) {
      newDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      // New field, default to descending for numbers, ascending for text
      newDirection = field === 'user' ? 'asc' : 'desc';
    }
    
    // Save sort preferences
    localStorage.setItem('monitorSortField', field);
    localStorage.setItem('monitorSortDirection', newDirection);
    
    // Update state and re-sort
    setSortField(field);
    setSortDirection(newDirection);
    
    setProcessInfo(prev => ({
      ...prev,
      processes: sortProcesses(prev.processes, field, newDirection)
    }));
  };

  // Manage auto-refresh interval
  useEffect(() => {
    // Clear existing interval
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
    }

    // Set new interval
    if (isIntervalRunning && intervalOption !== 'none') {
      const intervalMap = {
        '15s': 15000,
        '30s': 30000,
        '1m': 60000
      };

      intervalRef.current = setInterval(() => {
        fetchMonitoringData();
      }, intervalMap[intervalOption]);
    }

    // Cleanup interval
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [intervalOption, isIntervalRunning]);

  // Select refresh interval
  const handleIntervalSelect = (option) => {
    setIntervalOption(option);
    setIsIntervalRunning(option !== 'none');
    setIsIntervalDropdownOpen(false);
    localStorage.setItem('monitorRefreshInterval', option);
  };

  // Toggle interval freeze
  const toggleFreeze = () => {
    const newState = !isIntervalRunning;
    setIsIntervalRunning(newState);
    localStorage.setItem('monitorIntervalFrozen', String(!newState));
  };

  // Generate sort indicator for table headers
  const getSortIndicator = (field) => {
    if (sortField !== field) return null;
    
    return sortDirection === 'asc' 
      ? <ArrowUp className="h-3 w-3 inline ml-1" /> 
      : <ArrowDown className="h-3 w-3 inline ml-1" />;
  };

  return (
    <div className="w-full h-full">
      {isLoading && isInitialLoad ? (
        <div className="flex items-center justify-center h-full">
          <LoadingSpinner />
        </div>
      ) : (
        <>
          {/* Connection Control Section */}
          <div className="flex flex-col sm:flex-row items-center justify-between mb-6">
            <div className="flex items-center space-x-4 mb-4 sm:mb-0">
              {isConnected && (
                <div className="relative">
                  <button
                    onClick={() => setIsIntervalDropdownOpen(!isIntervalDropdownOpen)}
                    className="flex items-center space-x-2 bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg transition-all cursor-pointer"
                  >
                    <Clock className="h-4 w-4" />
                    <span>{intervalOption === 'none' ? 'Interval' : intervalOption}</span>
                  </button>
                  {isIntervalDropdownOpen && (
                    <div className="absolute z-10 mt-2 w-40 bg-black/95 text-white rounded-lg shadow-lg">
                      {['none', '15s', '30s', '1m'].map(option => (
                        <button
                          key={option}
                          onClick={() => handleIntervalSelect(option)}
                          className={`w-full text-left px-4 py-2 cursor-pointer rounded-lg hover:bg-white/10 ${
                            intervalOption === option ? 'bg-white/20' : ''
                          }`}
                        >
                          {option}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {isConnected && (
                <button
                  onClick={toggleFreeze}
                  className={`flex items-center space-x-2 px-4 py-2 cursor-pointer rounded-lg transition-all ${
                    isIntervalRunning 
                      ? 'bg-red-500/50 hover:bg-red-500/70' 
                      : 'bg-green-500/50 hover:bg-green-500/70'
                  } text-white`}
                >
                  {isIntervalRunning ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
                  <span>{isIntervalRunning ? 'Freeze' : 'Unfreeze'}</span>
                </button>
              )}
            </div>

            {isConnected && (
              <button
                onClick={fetchMonitoringData}
                disabled={isRefreshing}
                className="flex items-center cursor-pointer space-x-2 bg-white/10 hover:bg-white/20 text-white px-4 py-2 rounded-lg transition-all"
              >
                <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
                <span className="inline">Refresh</span>
              </button>
            )}
          </div>

          {/* System Information */}
          {isConnected && (
            <div className="space-y-6 pb-5">
              {/* System Overview */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="bg-black/20 border border-white/20 rounded-lg p-4 flex items-center space-x-4">
                  <Cpu className="h-8 w-8 text-blue-400" />
                  <div>
                    <h3 className="text-white font-semibold">CPU</h3>
                    <p className="text-gray-400 text-sm">
                      {processInfo.cpuInfo?.model || 'N/A'}
                    </p>
                    <p className="text-white">
                      {processInfo.cpuInfo?.usage || 'Calculating...'}%
                    </p>
                  </div>
                </div>

                <div className="bg-black/20 border border-white/20 rounded-lg p-4 flex items-center space-x-4">
                  <Server className="h-8 w-8 text-green-400" />
                  <div>
                    <h3 className="text-white font-semibold">Memory</h3>
                    <p className="text-gray-400 text-sm">Total: {processInfo.memoryInfo?.total || 'N/A'}</p>
                    <p className="text-white">
                      Used: {processInfo.memoryInfo?.used || 'Calculating...'}
                    </p>
                  </div>
                </div>

                <div className="bg-black/20 border border-white/20 rounded-lg p-4 flex items-center space-x-4">
                  <Activity className="h-8 w-8 text-purple-400" />
                  <div>
                    <h3 className="text-white font-semibold">System Load</h3>
                    <p className="text-gray-400 text-sm">1 min: {processInfo.systemLoad?.['1m'] || 'N/A'}</p>
                    <p className="text-white">
                      5 min: {processInfo.systemLoad?.['5m'] || 'Calculating...'}
                    </p>
                  </div>
                </div>
              </div>

              {/* Processes Table */}
              <div className="bg-black/20 border border-white/20 rounded-lg">
                <div className="flex items-center justify-between p-4 border-b border-white/10">
                  <div className="flex items-center space-x-2">
                    <List className="h-5 w-5 text-white" />
                    <h3 className="text-white font-semibold">Running Processes</h3>
                  </div>
                </div>
                <div className="max-h-80">
                  <CustomScrollbar style={{ height: '320px' }}>
                    <table className="w-full">
                      <thead className="sticky top-0 bg-black">
                        <tr className="text-gray-400 text-sm">
                          <th 
                            className="p-2 text-left cursor-pointer hover:text-white transition-colors"
                            onClick={() => handleSort('pid')}
                          >
                            PID {getSortIndicator('pid')}
                          </th>
                          <th 
                            className="p-2 text-left cursor-pointer hover:text-white transition-colors"
                            onClick={() => handleSort('user')}
                          >
                            User {getSortIndicator('user')}
                          </th>
                          <th 
                            className="p-2 text-left cursor-pointer hover:text-white transition-colors"
                            onClick={() => handleSort('cpu')}
                          >
                            CPU {getSortIndicator('cpu')}
                          </th>
                          <th 
                            className="p-2 text-left cursor-pointer hover:text-white transition-colors"
                            onClick={() => handleSort('memory')}
                          >
                            Mem {getSortIndicator('memory')}
                          </th>
                          <th className="p-2 text-left">Command</th>
                        </tr>
                      </thead>
                      <tbody>
                        {processInfo.processes.length > 0 ? (
                          processInfo.processes.map((process, index) => (
                            <tr 
                              key={index} 
                              className="border-t border-white/10 hover:bg-white/5 transition-colors"
                            >
                              <td className="p-2 text-white">{process.pid}</td>
                              <td className="p-2 text-white">{process.user}</td>
                              <td className="p-2 text-white">{process.cpu}%</td>
                              <td className="p-2 text-white">{process.memory}%</td>
                              <td className="p-2 text-white truncate max-w-xs">{process.command}</td>
                            </tr>
                          ))
                        ) : (
                          <tr>
                            <td colSpan="5" className="text-center text-gray-400 p-4">
                              No processes found
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </CustomScrollbar>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default Monitoring;
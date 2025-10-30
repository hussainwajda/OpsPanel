import React, { useState } from 'react';
import { 
  Play, 
  X, 
  Terminal,
  AlertCircle,
  Loader,
  Copy,
  Shield,
  ShieldOff,
  Code,
  FileCode
} from 'lucide-react';
import toast from 'react-hot-toast';
import CryptoJS from 'crypto-js';
import CustomScrollbar from './../CustomScrollbar.jsx';

const CustomCommands = () => {
  // Manage component state
  const [command, setCommand] = useState('');
  const [script, setScript] = useState('');
  const [output, setOutput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [isSudoMode, setIsSudoMode] = useState(
    localStorage.getItem('sudoMode') === 'false'
  );
  const [activeTab, setActiveTab] = useState('command'); // 'command' or 'script'

  // Toggle sudo mode with persistent storage
  const toggleSudoMode = () => {
    const newSudoMode = !isSudoMode;
    setIsSudoMode(newSudoMode);
    localStorage.setItem('sudoMode', newSudoMode.toString());
  };

  // Decrypt sensitive data securely
  const decryptData = (encryptedData) => {
    try {
      const key = import.meta.env.VITE_SSH_PASSWORD_KEY;
      return CryptoJS.AES.decrypt(encryptedData, key).toString(CryptoJS.enc.Utf8);
    } catch (error) {
      console.error("Error decrypting data:", error);
      return null;
    }
  };

  // Execute single command on remote server
  const executeCommand = async () => {
    // Validate command input
    if (!command.trim()) {
      toast.error('Please enter a command');
      return;
    }

    setIsLoading(true);
    setError(null);

    // Retrieve server connection details
    const username = localStorage.getItem('serverUsername');
    const ipAddress = localStorage.getItem('serverIpAddress');
    const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
    const sudoMode = localStorage.getItem('sudoMode') === 'true';
    
    // Validate connection details
    if (!username || !ipAddress) {
      setError('No connection details found. Please configure your server connection first.');
      setIsLoading(false);
      return;
    }

    // Check active server connection
    const isConnected = localStorage.getItem('connectionState') === 'connected';
    if (!isConnected) {
      setError('Not connected to any server. Please connect to a server first.');
      setIsLoading(false);
      return;
    }

    try {
      // Prepare authentication payload
      const payload = {
        username,
        ipAddress,
        authMethod,
        command: command,
        useSudo: sudoMode
      };

      // Handle authentication method specifics
      if (authMethod === 'password') {
        const savedEncryptedPassword = localStorage.getItem('serverPassword');
        if (!savedEncryptedPassword) {
          throw new Error('No password found. Please reconnect.');
        }
        const decryptedPassword = decryptData(savedEncryptedPassword);
        payload.password = CryptoJS.AES.encrypt(decryptedPassword, import.meta.env.VITE_SSH_PASSWORD_KEY).toString();
      } else {
        // Key file authentication
        const savedKeyFileName = localStorage.getItem('serverKeyFileName');
        const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
        if (!savedKeyFileName || !savedKeyFileContent) {
          throw new Error('No key file found. Please reconnect.');
        }
        payload.keyFileName = savedKeyFileName;
        payload.keyFileContent = savedKeyFileContent;
      }

      // Send command execution request
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/execute-command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Command execution failed');
      }

      // Update UI with command output
      setOutput(data.output || 'Command executed successfully');
      toast.success('Command executed successfully');
    } catch (error) {
      console.error('Error executing command:', error);
      setError(error.message || 'An error occurred while executing the command');
      toast.error(error.message || 'Command execution failed');
    } finally {
      setIsLoading(false);
    }
  };

  // Execute full script on remote server
  const executeScript = async () => {
    // Validate script input
    if (!script.trim()) {
      toast.error('Please enter a script');
      return;
    }

    setIsLoading(true);
    setError(null);

    // Retrieve server connection details
    const username = localStorage.getItem('serverUsername');
    const ipAddress = localStorage.getItem('serverIpAddress');
    const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
    const sudoMode = localStorage.getItem('sudoMode') === 'true';
    
    // Validate connection details
    if (!username || !ipAddress) {
      setError('No connection details found. Please configure your server connection first.');
      setIsLoading(false);
      return;
    }

    // Check active server connection
    const isConnected = localStorage.getItem('connectionState') === 'connected';
    if (!isConnected) {
      setError('Not connected to any server. Please connect to a server first.');
      setIsLoading(false);
      return;
    }

    try {
      // Prepare authentication payload
      const payload = {
        username,
        ipAddress,
        authMethod,
        scriptContent: script,
        useSudo: sudoMode
      };

      // Handle authentication method specifics
      if (authMethod === 'password') {
        const savedEncryptedPassword = localStorage.getItem('serverPassword');
        if (!savedEncryptedPassword) {
          throw new Error('No password found. Please reconnect.');
        }
        const decryptedPassword = decryptData(savedEncryptedPassword);
        payload.password = CryptoJS.AES.encrypt(decryptedPassword, import.meta.env.VITE_SSH_PASSWORD_KEY).toString();
      } else {
        // Key file authentication
        const savedKeyFileName = localStorage.getItem('serverKeyFileName');
        const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
        if (!savedKeyFileName || !savedKeyFileContent) {
          throw new Error('No key file found. Please reconnect.');
        }
        payload.keyFileName = savedKeyFileName;
        payload.keyFileContent = savedKeyFileContent;
      }

      // Send script execution request
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/execute-script`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Script execution failed');
      }

      // Update UI with script output
      setOutput(data.output || 'Script executed successfully');
      toast.success('Script executed successfully');
    } catch (error) {
      console.error('Error executing script:', error);
      setError(error.message || 'An error occurred while executing the script');
      toast.error(error.message || 'Script execution failed');
    } finally {
      setIsLoading(false);
    }
  };

  // Reset output area
  const clearOutput = () => {
    setOutput('');
    setError(null);
  };

  // Enable command execution on Enter key
  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !isLoading && activeTab === 'command' && !e.shiftKey) {
      executeCommand();
    }
  };

  // Dispatch execution based on active tab
  const handleExecute = () => {
    if (activeTab === 'command') {
      executeCommand();
    } else {
      executeScript();
    }
  };

  // Component render
  return (
    <div className="w-full max-w-4xl h-full bg-black/20 backdrop-blur-xl rounded-2xl border border-gray-900/50 flex flex-col overflow-hidden">
      {/* Command input area */}
      <div className="p-4 border-b border-gray-800 flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <Terminal className="h-5 w-5 text-white mr-2" />
            <h3 className="text-white font-semibold">Custom Command</h3>
          </div>
          
          <div className="flex items-center space-x-2">
            <button 
              onClick={toggleSudoMode}
              className={`p-2 rounded-lg cursor-pointer flex items-center ${isSudoMode ? 'bg-red-500/30 text-red-300' : 'text-gray-100 hover:text-white bg-green-700/80'}`}
              title={isSudoMode ? "Disable Sudo Mode" : "Enable Sudo Mode"}
            >
              {isSudoMode ? <ShieldOff className="h-5 w-5 mr-1" /> : <Shield className="h-5 w-5 mr-1" />}
              <span>sudo</span>
            </button>
          </div>
        </div>
        
        {/* Tabs for command/script switching */}
        <div className="flex border-b border-gray-800">
          <button
            onClick={() => setActiveTab('command')}
            className={`flex items-center cursor-pointer px-4 py-2 rounded-t-lg ${
              activeTab === 'command' 
                ? 'bg-white/10 text-white border-b-2 border-white' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <Terminal className="h-4 w-4 mr-2" />
            <span>Command</span>
          </button>
          <button
            onClick={() => setActiveTab('script')}
            className={`flex items-center cursor-pointer px-4 py-2 rounded-t-lg ${
              activeTab === 'script' 
                ? 'bg-white/10 text-white border-b-2 border-white' 
                : 'text-gray-400 hover:text-white'
            }`}
          >
            <FileCode className="h-4 w-4 mr-2" />
            <span>Script</span>
          </button>
        </div>
        
        <div className="flex flex-col space-y-2">
          {activeTab === 'command' ? (
            <div className="flex w-full">
              <div className="relative w-full">
                <input
                  type="text"
                  value={command}
                  onChange={(e) => setCommand(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Enter command to execute on the server..."
                  className="w-full bg-black/30 text-white px-4 py-3 rounded-l-lg border-r-0 focus:outline-none focus:ring-1 focus:ring-white/30"
                  disabled={isLoading}
                />
              </div>
              
              <button
                onClick={executeCommand}
                disabled={isLoading || !command.trim()}
                className={`px-4 py-3 rounded-r-lg flex items-center justify-center ${
                  isLoading || !command.trim()
                    ? 'bg-gray-700 cursor-not-allowed text-gray-400'
                    : 'bg-white/10 hover:bg-white/20 text-white cursor-pointer'
                }`}
                title="Execute command"
              >
                {isLoading ? (
                  <Loader className="h-5 w-5 animate-spin" />
                ) : (
                  <Play className="h-5 w-5" />
                )}
              </button>
            </div>
          ) : (
            <div className="flex flex-col w-full">
              <textarea
                value={script}
                onChange={(e) => setScript(e.target.value)}
                placeholder="#!/bin/bash
# Enter your script here
echo 'Hello from custom script!'
"
                className="w-full bg-black/30 text-white px-4 py-3 rounded-t-lg font-mono text-sm h-40 focus:outline-none focus:ring-1 focus:ring-white/30"
                disabled={isLoading}
              />
              
              <button
                onClick={executeScript}
                disabled={isLoading || !script.trim()}
                className={`px-4 py-3 rounded-b-lg flex items-center justify-center ${
                  isLoading || !script.trim()
                    ? 'bg-gray-700 cursor-not-allowed text-gray-400'
                    : 'bg-white/10 hover:bg-white/20 text-white cursor-pointer'
                }`}
                title="Execute script"
              >
                {isLoading ? (
                  <Loader className="h-5 w-5 animate-spin" />
                ) : (
                  <Play className="h-5 w-5 mr-2" />
                )}
                Execute Script
              </button>
            </div>
          )}
        </div>
      </div>
      
      {/* Output area */}
      <div className="flex-1 flex flex-col">
        <div className="px-4 py-2 bg-black/40 border-b border-gray-800 flex items-center justify-between">
          <span className="text-sm text-gray-400">Output</span>
          <div className="flex items-center space-x-2">
            {(output || error) && (
              <button
                onClick={clearOutput}
                className="p-1 rounded cursor-pointer text-gray-400 hover:text-white hover:bg-white/10"
                title="Clear output"
              >
                <X className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
        
        <div className="flex-1">
          <CustomScrollbar>
            {error ? (
              <div className="flex items-start space-x-2 p-4 bg-red-900/20 text-red-400">
                <AlertCircle className="h-5 w-5 mt-0.5 flex-shrink-0" />
                <pre className="text-sm whitespace-pre-wrap">{error}</pre>
              </div>
            ) : output ? (
              <pre className="p-4 text-white text-sm whitespace-pre-wrap font-mono">{output}</pre>
            ) : (
              <div className="flex items-center justify-center h-full text-gray-400 text-sm">
                {activeTab === 'command' ? 'Execute a command' : 'Execute a script'} to see the output here
              </div>
            )}
          </CustomScrollbar>
        </div>
      </div>
    </div>
  );
};

export default CustomCommands;
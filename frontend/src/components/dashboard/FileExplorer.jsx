import React, { useState, useEffect, useCallback } from 'react';
import { 
  Folder, 
  File, 
  ChevronLeft, 
  ChevronRight, 
  RefreshCw, 
  Home as HomeIcon,
  Eye,
  EyeOff,
  Search,
  FileText,
  Loader,
  AlertCircle,
  Link as LinkIcon,
  X,
  ArrowLeft,
  Check as CheckIcon,
  ShieldOff, 
  Shield
} from 'lucide-react';
import toast from 'react-hot-toast';
import CryptoJS from 'crypto-js';
import CustomScrollbar from './../CustomScrollbar.jsx';

const FileExplorer = () => {
  // Component state management
  const [currentPath, setCurrentPath] = useState('/');
  const [fileList, setFileList] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState(['/']);
  const [historyIndex, setHistoryIndex] = useState(0);
  const [showHiddenFiles, setShowHiddenFiles] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [fileContent, setFileContent] = useState(null);
  const [viewingFile, setViewingFile] = useState(null);
  const [isEditingPath, setIsEditingPath] = useState(false);
  const [editedPath, setEditedPath] = useState(currentPath);
  const [isSudoMode, setIsSudoMode] = useState(
    localStorage.getItem('sudoMode') === 'false'
  );

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

  // Convert bytes to human-readable file size
  const formatFileSize = (sizeInBytes) => {
    const bytes = parseInt(sizeInBytes);
    
    if (isNaN(bytes)) return sizeInBytes;
    
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  };

  // Parse ls -la command output with advanced handling
  const parseLsOutput = (output, path) => {
    const lines = output.split('\n');
    const parsedFiles = [];
  
    // Skip the first line (total) and start from index 1
    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      // Regex to parse ls -la output with robust file details
      const regex = /^([drwx-]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+([A-Za-z]+\s+\d+\s+(?:\d{4}|\d{2}:\d{2}))\s+(.+)$/;
      const match = line.match(regex);
      
      if (!match) continue;
      
      const [, permissions, , owner, group, size, dateStr, nameAndTarget] = match;
      const fileType = permissions[0];
  
      // Handle symlink parsing
      let name, target, fullTarget;
      if (fileType === 'l' && nameAndTarget.includes(' -> ')) {
        [name, fullTarget] = nameAndTarget.split(' -> ');
        
        // Remove .usr-is-merged suffix from name
        name = name.replace(/\.usr-is-merged$/, '');
        
        // Simplify displayed target
        target = fullTarget.split('/').pop().replace(/\.usr-is-merged$/, '');
      } else {
        // Remove .usr-is-merged suffix from regular files and directories
        name = nameAndTarget.replace(/\.usr-is-merged$/, '');
        target = null;
        fullTarget = null;
      }
      
      // Skip "." and ".." entries
      if (name === '.' || name === '..') {
        continue;
      }
      
      parsedFiles.push({
        name,
        path: path === '/' ? `/${name}` : `${path}/${name}`,
        isDirectory: fileType === 'd',
        isSymlink: fileType === 'l',
        symlinkTarget: target,
        symlinkFullTarget: fullTarget,
        permissions: permissions.substring(1),
        owner,
        group,
        size,
        date: dateStr,
        isHidden: name.startsWith('.'),
      });
    }
  
    return parsedFiles;
  };

  // Fetch directory contents via SSH
  const fetchDirectoryContents = useCallback(async (path) => {
    setIsLoading(true);
    setError(null);
    setFileList([]);
  
    // Retrieve server connection details
    const username = localStorage.getItem('serverUsername');
    const ipAddress = localStorage.getItem('serverIpAddress');
    const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
    const sudoMode = localStorage.getItem('sudoMode') === 'true';
    
    if (!username || !ipAddress) {
      setError('No connection details found. Please configure your server connection first.');
      setIsLoading(false);
      return;
    }

    // Validate active server connection
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
        command: sudoMode 
          ? `sudo ls -la "$(readlink -f "${path}")"` 
          : `ls -la "$(readlink -f "${path}")"`,
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

      // Execute remote directory listing
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/execute-command`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });
  
      const data = await response.json();
  
      if (!data.success) {
        throw new Error(data.message || 'Failed to list directory contents');
      }
  
      // Parse command output and update state
      const parsedFiles = parseLsOutput(data.output, path);
      setFileList(parsedFiles);
    } catch (error) {
      console.error('Error fetching directory contents:', error);
      setError(error.message || 'An error occurred while listing directory contents');
      toast.error(error.message || 'Failed to list directory contents');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Trigger initial load and update on path changes
  useEffect(() => {
    if (currentPath && !isSearching) {
      fetchDirectoryContents(currentPath);
      setEditedPath(currentPath);
    }
  }, [currentPath, fetchDirectoryContents, isSearching]);

  // Directory navigation handler
  const navigateToDirectory = (path) => {
    // Manage navigation history
    if (historyIndex === history.length - 1) {
      setHistory([...history.slice(0, historyIndex + 1), path]);
      setHistoryIndex(historyIndex + 1);
    } else {
      // Handle navigation after going back
      setHistory([...history.slice(0, historyIndex + 1), path]);
      setHistoryIndex(historyIndex + 1);
    }
    
    setCurrentPath(path);
    setIsSearching(false);
    setSearchTerm('');
  };

  // Navigate to parent directory
  const navigateToParentDirectory = () => {
    if (currentPath === '/') return;
    
    const parentPath = currentPath.substring(0, currentPath.lastIndexOf('/')) || '/';
    navigateToDirectory(parentPath);
  };

  // More navigation methods (goBack, goForward, goToHome, etc.)
  const goBack = () => {
    if (historyIndex > 0) {
      setHistoryIndex(historyIndex - 1);
      setCurrentPath(history[historyIndex - 1]);
      setIsSearching(false);
      setSearchTerm('');
    }
  };

  const handleClearSearch = () => {
    setSearchTerm('');
    setIsSearching(false);
    fetchDirectoryContents(currentPath);
  };

  const goForward = () => {
    if (historyIndex < history.length - 1) {
      setHistoryIndex(historyIndex + 1);
      setCurrentPath(history[historyIndex + 1]);
      setIsSearching(false);
      setSearchTerm('');
    }
  };

  const goToHome = () => {
    navigateToDirectory('/');
  };

  const handleRefresh = () => {
    fetchDirectoryContents(currentPath);
  };

  const toggleHiddenFiles = () => {
    setShowHiddenFiles(!showHiddenFiles);
  };

// Perform remote directory search
const handleSearch = async () => {
  const sudoMode = localStorage.getItem('sudoMode') === 'true';

  if (!searchTerm.trim()) {
    return;
  }

  setIsLoading(true);
  setError(null);
  setIsSearching(true);

  // Retrieve server connection details
  const username = localStorage.getItem('serverUsername');
  const ipAddress = localStorage.getItem('serverIpAddress');
  const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
  
  if (!username || !ipAddress) {
    setError('No connection details found. Please configure your server connection first.');
    setIsLoading(false);
    return;
  }

  try {
    // Prepare authentication payload
    const payload = {
      username,
      ipAddress,
      authMethod,
      // Use ls -la with grep for more accurate results
      command: sudoMode
        ? `sudo ls -la "${currentPath}" | grep -i "${searchTerm}"`
        : `ls -la "${currentPath}" | grep -i "${searchTerm}"`,
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

    // Execute search request
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/execute-command`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!data.success) {
      throw new Error(data.message || 'Search failed');
    }

    // Add total line to ensure compatibility with parseLsOutput
    const completeOutput = `total 0\n${data.output}`;
    
    // Parse search results
    const parsedFiles = parseLsOutput(completeOutput, currentPath);
    setFileList(parsedFiles);
    
    const resultCount = parsedFiles.length;
    toast.success(`Found ${resultCount} result${resultCount !== 1 ? 's' : ''} for "${searchTerm}"`);
  } catch (error) {
    console.error('Search error:', error);
    setError(error.message || 'An error occurred during search');
    toast.error(error.message || 'Search failed');
  } finally {
    setIsLoading(false);
  }
};

// Get detailed file information
const getFileInfo = async (filePath) => {
  // Retrieve server connection details
  const username = localStorage.getItem('serverUsername');
  const ipAddress = localStorage.getItem('serverIpAddress');
  const authMethod = localStorage.getItem('serverAuthMethod') || 'password';

  try {
    // Prepare authentication payload
    const payload = {
      username,
      ipAddress,
      authMethod,
      command: `ls -la "${filePath}"`,
    };

    // Handle authentication method specifics
    if (authMethod === 'password') {
      const savedEncryptedPassword = localStorage.getItem('serverPassword');
      const decryptedPassword = decryptData(savedEncryptedPassword);
      payload.password = CryptoJS.AES.encrypt(decryptedPassword, import.meta.env.VITE_SSH_PASSWORD_KEY).toString();
    } else {
      // Key file authentication
      const savedKeyFileName = localStorage.getItem('serverKeyFileName');
      const savedKeyFileContent = localStorage.getItem('serverKeyFileContent');
      payload.keyFileName = savedKeyFileName;
      payload.keyFileContent = savedKeyFileContent;
    }

    // Execute file info request
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/execute-command`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!data.success) {
      return null;
    }

    // Parse single file result
    const parsedFiles = parseLsOutput(data.output, filePath.substring(0, filePath.lastIndexOf('/')));
    return parsedFiles.length > 0 ? parsedFiles[0] : null;
  } catch (error) {
    console.error('Error getting file info:', error);
    return null;
  }
};

// View text file contents
const viewTextFile = async (file) => {
  setIsLoading(true);
  try {
    // Retrieve server connection details
    const username = localStorage.getItem('serverUsername');
    const ipAddress = localStorage.getItem('serverIpAddress');
    const authMethod = localStorage.getItem('serverAuthMethod') || 'password';
    
    if (!username || !ipAddress) {
      throw new Error('No connection details found. Please configure your server connection first.');
    }

    // Prepare authentication payload
    const payload = {
      username,
      ipAddress,
      authMethod,
      command: `cat "${file.path}"`,
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

    // Execute file view request
    const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/execute-command`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    const data = await response.json();

    if (!data.success) {
      throw new Error(data.message || 'Failed to read file');
    }

    setFileContent(data.output);
    setViewingFile(file);
  } catch (error) {
    console.error('Error viewing file:', error);
    toast.error(error.message || 'Failed to read file');
  } finally {
    setIsLoading(false);
  }
};

// Close file viewer
const closeFileViewer = () => {
  setFileContent(null);
  setViewingFile(null);
};

// Determine if a file is likely a text file
const isTextFile = (fileName) => {
  // Exclude known binary formats
  const binaryExtensions = [
    'pdf', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'mp3', 'mp4', 'avi', 'mov', 'mkv', 'zip', 
    'tar', 'gz', 'tgz', 'rar', '7z', 'exe', 'dll', 'so', 'dylib', 'bin', 'iso', 'dmg'
  ];
  
  // Treat files without an extension as text
  if (!fileName.includes('.')) {
    return true;
  }
  
  const extension = fileName.split('.').pop().toLowerCase();
  return !binaryExtensions.includes(extension);
};

// Handle file/directory click
const handleFileClick = (file) => {
  if (file.isDirectory) {
    navigateToDirectory(file.path);
  } else if (file.isSymlink) {
    // Follow symlinks to directories or files
    if (file.symlinkTarget && !file.symlinkTarget.includes('/')) {
      const targetPath = currentPath === '/' 
        ? `/${file.symlinkTarget}` 
        : `${currentPath}/${file.symlinkTarget}`;
      navigateToDirectory(targetPath);
    } else if (file.symlinkTarget && file.symlinkTarget.startsWith('/')) {
      // Handle absolute path symlinks
      navigateToDirectory(file.symlinkTarget);
    }
  } else if (isTextFile(file.name)) {
    viewTextFile(file);
  }
};

// Filter files based on hidden files setting
const filteredFiles = fileList.filter(file => showHiddenFiles || !file.isHidden);

// Render file viewer when a file is being viewed
if (viewingFile && fileContent !== null) {
  return (
    <div className="w-full h-full flex flex-col bg-black/20 backdrop-blur-xl rounded-2xl border border-gray-900/50 overflow-hidden">
      {/* File viewer header */}
      <div className="p-4 border-b border-gray-800 flex items-center justify-between">
        <div className="flex items-center">
          <button 
            onClick={closeFileViewer}
            className="p-2 rounded-lg cursor-pointer text-gray-400 hover:text-white hover:bg-white/10 mr-2"
            title="Back to file explorer"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>
          <div className="bg-black/30 text-white px-3 py-2 rounded-lg overflow-x-auto whitespace-nowrap text-sm">
            {viewingFile.path}
          </div>
        </div>
        <button 
          onClick={closeFileViewer}
          className="p-2 rounded-lg cursor-pointer text-gray-400 hover:text-white hover:bg-white/10"
          title="Close file viewer"
        >
          <X className="h-5 w-5" />
        </button>
      </div>
      
      {/* File content with custom scrollbar */}
      <div className="flex-1 bg-black/10">
        <CustomScrollbar>
          <pre className="text-white text-sm font-mono whitespace-pre-wrap p-4">{fileContent}</pre>
        </CustomScrollbar>
      </div>
    </div>
  );
}

// Main file explorer render
return (
  <div className="w-full h-full flex flex-col bg-black/20 backdrop-blur-xl rounded-2xl border border-gray-900/50 overflow-hidden">
    {/* Toolbar */}
    <div className="p-4 border-b border-gray-800 flex flex-col gap-2">
      {/* Navigation buttons */}
      <div className="flex flex-wrap items-center gap-2 w-full">
        <button 
          onClick={goBack} 
          disabled={historyIndex === 0}
          className={`p-2 rounded-lg ${historyIndex === 0 ? 'text-gray-600 cursor-not-allowed' : 'text-gray-400 hover:text-white cursor-pointer hover:bg-white/10'}`}
          title="Go back"
        >
          <ChevronLeft className="h-5 w-5" />
        </button>
        
        <button 
          onClick={goForward} 
          disabled={historyIndex >= history.length - 1}
          className={`p-2 rounded-lg ${historyIndex >= history.length - 1 ? 'text-gray-600 cursor-not-allowed' : 'text-gray-400 hover:text-white cursor-pointer hover:bg-white/10'}`}
          title="Go forward"
        >
          <ChevronRight className="h-5 w-5" />
        </button>
        
        <button 
          onClick={goToHome}
          className="p-2 rounded-lg cursor-pointer text-gray-400 hover:text-white hover:bg-white/10"
          title="Go to root directory"
        >
          <HomeIcon className="h-5 w-5" />
        </button>
        
        <button 
          onClick={handleRefresh}
          className="p-2 rounded-lg cursor-pointer text-gray-400 hover:text-white hover:bg-white/10"
          title="Refresh"
        >
          <RefreshCw className={`h-5 w-5 ${isLoading ? 'animate-spin' : ''}`} />
        </button>

        <button 
          onClick={toggleSudoMode}
          className={`p-2 rounded-lg cursor-pointer flex items-center ${isSudoMode ? 'bg-red-500/30 text-red-300' : 'text-gray-400 hover:text-white hover:bg-white/10'}`}
          title={isSudoMode ? "Disable Sudo Mode" : "Enable Sudo Mode"}
        >
          {isSudoMode ? <ShieldOff className="h-5 w-5 mr-1" /> : <Shield className="h-5 w-5 mr-1" />}
          <span className='block'>sudo</span>
        </button>
        
        <button 
          onClick={toggleHiddenFiles}
          className={`p-2 rounded-lg cursor-pointer ${showHiddenFiles ? 'bg-white/10 text-white' : 'text-gray-400 hover:text-white hover:bg-white/10'}`}
          title={showHiddenFiles ? "Hide hidden files" : "Show hidden files"}
        >
          {showHiddenFiles ? <Eye className="h-5 w-5" /> : <EyeOff className="h-5 w-5" />}
        </button>
      </div>
      
      {/* Path and search row */}
      <div className="flex flex-col sm:flex-row gap-2 w-full">
        {/* Path editing section */}
        <div className="relative w-full">
          {!isEditingPath ? (
            <div 
              className="bg-black/30 text-white px-3 py-2 rounded-lg w-full overflow-x-auto whitespace-nowrap text-sm cursor-pointer"
              onClick={() => setIsEditingPath(true)}
            >
              {currentPath}
            </div>
          ) : (
            <div className="flex items-center space-x-2">
              <input
                type="text"
                value={editedPath}
                onChange={(e) => setEditedPath(e.target.value)}
                className="bg-black/30 text-white pl-3 pr-10 py-2 rounded-lg w-full focus:outline-none focus:ring-1 focus:ring-white/30 text-sm"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      navigateToDirectory(editedPath);
                      setIsEditingPath(false);
                    } else if (e.key === 'Escape') {
                      setIsEditingPath(false);
                      setEditedPath(currentPath);
                    }
                  }}
                  autoFocus
                />
                <button
                  onClick={() => {
                    navigateToDirectory(editedPath);
                    setIsEditingPath(false);
                  }}
                  className="p-2 rounded-lg cursor-pointer text-green-400 hover:text-green-300"
                  title="Navigate to path"
                >
                  <CheckIcon className="h-5 w-5" />
                </button>
                <button
                  onClick={() => {
                    setIsEditingPath(false);
                    setEditedPath(currentPath);
                  }}
                  className="p-2 rounded-lg cursor-pointer text-red-400 hover:text-red-300"
                  title="Cancel"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            )}
          </div>
          
          {/* Search input section */}
          <div className="relative w-full sm:w-64 md:w-72 lg:w-80">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search files..."
              className="bg-black/30 text-white pl-3 pr-10 py-2 rounded-lg w-full focus:outline-none focus:ring-1 focus:ring-white/30 text-sm"
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button
              onClick={isSearching ? handleClearSearch : handleSearch}
              className="absolute cursor-pointer right-0 top-0 h-full px-3 text-gray-400 hover:text-white"
              title={isSearching ? "Clear search" : "Search"}
            >
              {isSearching ? <X className="h-4 w-4" /> : <Search className="h-4 w-4" />}
            </button>
          </div>
        </div>
      </div>
      
      {/* File listing with custom scrollbar */}
      <div className="flex-1">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <Loader className="h-6 w-6 text-white animate-spin mr-2" />
            <p className="text-white">Loading...</p>
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-6">
            <AlertCircle className="h-12 w-12 text-red-500 mb-4" />
            <h3 className="text-white text-lg font-semibold mb-2">Error</h3>
            <p className="text-gray-400 max-w-md">{error}</p>
          </div>
        ) : filteredFiles.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center p-6">
            <FileText className="h-12 w-12 text-gray-500 mb-4" />
            <h3 className="text-white text-lg font-semibold mb-2">No files found</h3>
            <p className="text-gray-400 max-w-md">
              {isSearching 
                ? `No results found for "${searchTerm}" in this directory.` 
                : "This directory is empty."
              }
            </p>
          </div>
        ) : (
          <CustomScrollbar>
            <div className="w-full">
              <table className="min-w-full divide-y divide-gray-800">
                <thead className="bg-black sticky top-0 z-10">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider w-5/12">Name</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider hidden sm:table-cell">Permissions</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider hidden md:table-cell">Owner</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider hidden lg:table-cell">Size</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider hidden xl:table-cell">Modified</th>
                  </tr>
                </thead>
                <tbody className="bg-black/10 divide-y divide-gray-800">
                  {/* Custom ".." back button */}
                  {!isSearching && currentPath !== '/' && (
                    <tr className="hover:bg-white/5 cursor-pointer" onClick={navigateToParentDirectory}>
                      <td className="px-6 py-3 whitespace-nowrap">
                        <div className="flex items-center">
                          <Folder className="h-5 w-5 text-blue-400 mr-3" />
                          <span className="text-white">..</span>
                        </div>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden sm:table-cell">
                        <span className="text-gray-400">-</span>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden md:table-cell">
                        <span className="text-gray-400">-</span>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden lg:table-cell">
                        <span className="text-gray-400">-</span>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden xl:table-cell">
                        <span className="text-gray-400">-</span>
                      </td>
                    </tr>
                  )}
                  
                  {filteredFiles.map((file, index) => (
                    <tr 
                      key={index} 
                      className={`hover:bg-white/5 cursor-pointer`}
                      onClick={() => handleFileClick(file)}
                    >
                      <td className="px-6 py-3 whitespace-nowrap">
                        <div className="flex items-center">
                          {file.isDirectory ? (
                            <Folder className="h-5 w-5 text-blue-400 mr-3" />
                          ) : file.isSymlink ? (
                            <LinkIcon className="h-5 w-5 text-purple-400 mr-3" />
                          ) : (
                            <File className="h-5 w-5 text-gray-400 mr-3" />
                          )}
                          <span className={`${file.isHidden ? 'text-gray-500' : 'text-white'}`}>
                            {file.name}
                          </span>
                        </div>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden sm:table-cell">
                        <span className="text-gray-400 font-mono text-xs">{file.permissions}</span>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden md:table-cell">
                        <span className="text-gray-400">{file.owner}</span>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden lg:table-cell">
                        <span className="text-gray-400">{formatFileSize(file.size)}</span>
                      </td>
                      <td className="px-6 py-3 whitespace-nowrap hidden xl:table-cell">
                        <span className="text-gray-400">{file.date}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CustomScrollbar>
        )}
      </div>
    </div>
  );
};

export default FileExplorer;
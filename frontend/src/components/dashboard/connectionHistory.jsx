"use client"

import { useState, useEffect } from "react"
import { motion } from "framer-motion"
import { Server, User, Plug, Trash2, Loader } from "lucide-react"
import toast from "react-hot-toast"
import { getCookie } from "../../utils/generateToken.js"

// Format time ago
const formatTimeAgo = (dateString) => {
  const date = new Date(dateString)
  const now = new Date()
  const diffInSeconds = Math.floor((now - date) / 1000)
  
  if (diffInSeconds < 60) return "Just now"
  if (diffInSeconds < 3600) {
    const minutes = Math.floor(diffInSeconds / 60)
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`
  }
  if (diffInSeconds < 86400) {
    const hours = Math.floor(diffInSeconds / 3600)
    return `${hours} hour${hours > 1 ? 's' : ''} ago`
  }
  if (diffInSeconds < 604800) {
    const days = Math.floor(diffInSeconds / 86400)
    return `${days} day${days > 1 ? 's' : ''} ago`
  }
  return date.toLocaleDateString()
}

const ConnectionHistory = ({ onConnectFromHistory, onRefresh }) => {
  const [connections, setConnections] = useState([])
  const [isLoading, setIsLoading] = useState(true)
  const [deletingId, setDeletingId] = useState(null)
  const [connectingId, setConnectingId] = useState(null)

  // Fetch connection history from API
  const fetchConnectionHistory = async () => {
    try {
      setIsLoading(true)
      const authToken = getCookie('authToken')
      
      console.log('Fetching connection history...', { authToken: authToken ? 'Token found' : 'No token' })
      
      if (!authToken) {
        console.warn('No auth token found - connection history will not be saved')
        setConnections([])
        setIsLoading(false)
        return
      }

      const apiUrl = `${import.meta.env.VITE_API_BASE_URL}/api/connection-history/`
      console.log('Fetching from:', apiUrl)

      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Token ${authToken}`
        }
      })
      
      console.log('Connection history response status:', response.status)

      if (!response.ok) {
        if (response.status === 401) {
          toast.error('Authentication required. Please sign in again.')
          return
        }
        throw new Error('Failed to fetch connection history')
      }

      const data = await response.json()
      console.log('Connection history data:', data)
      
      if (data.success) {
        const connectionsList = data.connections || []
        console.log(`Loaded ${connectionsList.length} connection(s) from history`)
        setConnections(connectionsList)
      } else {
        throw new Error(data.message || 'Failed to fetch connection history')
      }
    } catch (error) {
      console.error('Error fetching connection history:', error)
      toast.error(error.message || 'Failed to load connection history')
      setConnections([])
    } finally {
      setIsLoading(false)
    }
  }

  // Expose refresh function to parent via useEffect
  useEffect(() => {
    if (onRefresh) {
      // Store the refresh function in the callback
      onRefresh(fetchConnectionHistory)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onRefresh])

  // Connect from history
  const handleConnect = async (connection) => {
    try {
      setConnectingId(connection.id)
      const authToken = getCookie('authToken')
      
      if (!authToken) {
        toast.error('Authentication required. Please sign in again.')
        return
      }

      toast.loading(`Connecting to ${connection.server_username}@${connection.server_ip}...`, {
        id: `connect-${connection.id}`
      })

      const response = await fetch(
        `${import.meta.env.VITE_API_BASE_URL}/api/connection-history/${connection.id}/connect/`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Token ${authToken}`
          }
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Failed to connect')
      }

      if (data.success) {
        // Update connection state
        localStorage.setItem('connectionState', 'connected')
        localStorage.setItem('serverOsType', data.osType)
        localStorage.setItem('serverUsername', connection.server_username)
        localStorage.setItem('serverIpAddress', connection.server_ip)
        localStorage.setItem('serverAuthMethod', connection.auth_method)
        
        // Refresh history to update last_connected
        await fetchConnectionHistory()
        
        // Call parent handler if provided
        if (onConnectFromHistory) {
          onConnectFromHistory(connection)
        }
        
        toast.success(`Connected to ${data.osType} server!`, {
          id: `connect-${connection.id}`
        })
      } else {
        throw new Error(data.message || 'Connection failed')
      }
    } catch (error) {
      console.error('Error connecting from history:', error)
      toast.error(error.message || 'Failed to connect to server', {
        id: `connect-${connection.id}`
      })
    } finally {
      setConnectingId(null)
    }
  }

  // Delete connection history
  const handleDelete = async (connection) => {
    // Confirm deletion
    const confirmed = window.confirm(
      `Are you sure you want to delete the connection history for ${connection.server_username}@${connection.server_ip}?`
    )
    
    if (!confirmed) return

    try {
      setDeletingId(connection.id)
      const authToken = getCookie('authToken')
      
      if (!authToken) {
        toast.error('Authentication required. Please sign in again.')
        return
      }

      toast.loading('Deleting connection history...', {
        id: `delete-${connection.id}`
      })

      const response = await fetch(
        `${import.meta.env.VITE_API_BASE_URL}/api/connection-history/${connection.id}/`,
        {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Token ${authToken}`
          }
        }
      )

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.message || 'Failed to delete connection history')
      }

      if (data.success) {
        // Remove from local state
        setConnections(prev => prev.filter(conn => conn.id !== connection.id))
        toast.success('Connection history deleted successfully', {
          id: `delete-${connection.id}`
        })
      } else {
        throw new Error(data.message || 'Failed to delete')
      }
    } catch (error) {
      console.error('Error deleting connection history:', error)
      toast.error(error.message || 'Failed to delete connection history', {
        id: `delete-${connection.id}`
      })
    } finally {
      setDeletingId(null)
    }
  }

  // Fetch history on component mount
  useEffect(() => {
    console.log('ConnectionHistory component mounted, fetching history...')
    fetchConnectionHistory()
  }, [])

  // Container animation for the entire list
  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2,
      },
    },
  }

  // Individual card animation
  const cardVariants = {
    hidden: { opacity: 0, y: 20, scale: 0.95 },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        type: "spring",
        stiffness: 100,
        damping: 12,
      },
    },
  }

  // Hover animation
  const hoverVariants = {
    hover: {
      scale: 1.02,
      y: -4,
      transition: {
        type: "spring",
        stiffness: 300,
        damping: 10,
      },
    },
  }

  return (
    <div className="w-full max-w-sm">
      <div className="mb-4">
        <h3 className="text-lg font-bold text-white flex items-center gap-2">
          <Server className="h-5 w-5 text-blue-400" />
          Connection History
        </h3>
        <p className="text-xs text-gray-400 mt-1">Quick access to your previous connections</p>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader className="h-6 w-6 animate-spin text-blue-400" />
        </div>
      ) : connections.length === 0 ? (
        <div className="text-center py-8 text-gray-400 text-sm">
          No connection history found
        </div>
      ) : (
        <motion.div 
          className="space-y-3 max-h-[600px] overflow-y-auto" 
          variants={containerVariants} 
          initial="hidden" 
          animate="visible"
        >
          {connections.map((connection) => (
            <motion.div
              key={connection.id}
              variants={cardVariants}
              whileHover="hover"
              className="group bg-black/20 backdrop-blur-xl p-4 rounded-xl border border-gray-900/50 hover:border-blue-500/30 transition-all duration-200 shadow-lg overflow-hidden"
            >
              <motion.div
                className="absolute inset-0 bg-gradient-to-r from-blue-500/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none"
                initial={{ opacity: 0 }}
                whileHover={{ opacity: 1 }}
              />

              <div className="relative z-10">
                {/* Header with IP and Username */}
                <div className="flex items-start justify-between mb-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Server className="h-4 w-4 text-gray-400" />
                      <span className="text-sm font-mono text-white font-semibold">
                        {connection.server_ip}
                      </span>
                      {connection.server_port !== 22 && (
                        <span className="text-xs text-gray-500">:{connection.server_port}</span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 ml-1">
                      <User className="h-3 w-3 text-gray-500" />
                      <span className="text-xs text-gray-300">{connection.server_username}</span>
                    </div>
                  </div>
                  
                  {/* Delete button */}
                  <motion.button
                    onClick={(e) => {
                      e.stopPropagation()
                      handleDelete(connection)
                    }}
                    disabled={deletingId === connection.id}
                    whileTap={{ scale: 0.95 }}
                    className="p-1.5 text-gray-400 hover:text-red-400 transition-colors disabled:opacity-50"
                    title="Delete connection history"
                  >
                    {deletingId === connection.id ? (
                      <Loader className="h-4 w-4 animate-spin" />
                    ) : (
                      <Trash2 className="h-4 w-4" />
                    )}
                  </motion.button>
                </div>

                {/* Footer with last connected and button */}
                <div className="flex items-center justify-between">
                  <span className="text-xs text-gray-400">
                    {formatTimeAgo(connection.last_connected)}
                  </span>

                  <motion.button
                    onClick={() => handleConnect(connection)}
                    disabled={connectingId === connection.id || deletingId === connection.id}
                    whileTap={{ scale: 0.95 }}
                    className="flex items-center gap-1 px-3 py-1.5 bg-gradient-to-r from-blue-500/20 to-blue-600/20 hover:from-blue-500/30 hover:to-blue-600/30 text-blue-300 hover:text-blue-200 text-xs font-medium rounded-lg border border-blue-500/30 hover:border-blue-500/50 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {connectingId === connection.id ? (
                      <>
                        <Loader className="h-3 w-3 animate-spin" />
                        Connecting...
                      </>
                    ) : (
                      <>
                        <Plug className="h-3 w-3" />
                        Connect
                      </>
                    )}
                  </motion.button>
                </div>
              </div>
            </motion.div>
          ))}
        </motion.div>
      )}
    </div>
  )
}

export default ConnectionHistory

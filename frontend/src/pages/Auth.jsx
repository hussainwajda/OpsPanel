import React, { useState, useRef, useEffect } from 'react';
import { 
  Lock, 
  Mail, 
  User, 
  Eye, 
  EyeOff, 
  ArrowLeft, 
  ArrowRight 
} from 'lucide-react';
import toast from 'react-hot-toast';
import ToastContainer from '../components/ToastContainer';
import CryptoJS from 'crypto-js';
import { decryptToken, generateToken, setCookie } from '../utils/generateToken.js';
import { getPublicIP } from '../utils/getPublicIP.js';
import { useNavigate } from 'react-router-dom';

// AES encryption key from environment
const SECRET_KEY = import.meta.env.VITE_AES_AUTH_PASSWORD_KEY;

// Encrypt password using AES
const encryptPassword = (password) => {
  try {
    return CryptoJS.AES.encrypt(password, SECRET_KEY).toString();
  } catch (error) {
    console.error('Encryption error:', error);
    return null;
  }
};

// Authentication API handler
const authApi = async (payload) => {
  try {
    // Generate and attach device token
    const token = await generateToken();

    // Retrieve public IP
    const publicIP = await getPublicIP();
    console.log("Token: ", token);
    console.log("Public Ip: ",publicIP)
    const response = await fetch(
      `${import.meta.env.VITE_API_BASE_URL}/api/auth/,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Device-Token": token,
          "X-Public-IP": publicIP || "Unknown",
        },
        body: JSON.stringify(payload),
      }`
    );

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.message || "Authentication failed");
    }

    return await response.json();
  } catch (error) {
    console.error("Authentication error:", error);
    throw error;
  }
};

const Auth = () => {
  const inputRef = useRef(null);
  const [isSignin, setIsSignin] = useState(true);
  const [currentStep, setCurrentStep] = useState(1);
  const [showPassword, setShowPassword] = useState(false);
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  });

  // Auto-focus input on step change
  useEffect(() => {
    if (inputRef.current) {
      inputRef.current.focus();
    }
  }, [currentStep, isSignin]);

  const totalSteps = isSignin ? 2 : 4;

  // Handle input changes with validation
  const handleInputChange = (e) => {
    const { value } = e.target;
    
    // Validate username input
    if (getCurrentInputName() === 'username') {
      // Allow only alphabetical characters
      const alphabeticValue = value.replace(/[^a-zA-Z]/g, '');
      
      // Limit to 10 characters
      const trimmedValue = alphabeticValue.slice(0, 10);
      
      setFormData(prev => ({
        ...prev,
        username: trimmedValue
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [getCurrentInputName()]: value
      }));
    }
  };

  // Determine current input field name
  const getCurrentInputName = () => {
    if (isSignin) {
      return currentStep === 1 ? 'email' : 'password';
    }
    
    switch(currentStep) {
      case 1: return 'username';
      case 2: return 'email';
      case 3: return 'password';
      case 4: return 'confirmPassword';
      default: return 'username';
    }
  };

  // Determine input type dynamically
  const getCurrentInputType = () => {
    if (isSignin) {
      return currentStep === 1 ? 'email' : showPassword ? 'text' : 'password';
    }
    
    switch(currentStep) {
      case 1: return 'text';
      case 2: return 'email';
      case 3: return showPassword ? 'text' : 'password';
      case 4: return showPassword ? 'text' : 'password';
      default: return 'text';
    }
  };

  // Get current input label
  const getCurrentLabel = () => {
    if (isSignin) {
      return currentStep === 1 ? 'Email Address' : 'Password';
    }
    
    switch(currentStep) {
      case 1: return 'Username';
      case 2: return 'Email Address';
      case 3: return 'Password';
      case 4: return 'Confirm Password';
      default: return '';
    }
  };

  // Get current input placeholder
  const getCurrentPlaceholder = () => {
    if (isSignin) {
      return currentStep === 1 ? 'Enter your email' : 'Enter your password';
    }
    
    switch(currentStep) {
      case 1: return 'Choose a username';
      case 2: return 'Enter your email address';
      case 3: return 'Create a password';
      case 4: return 'Confirm your password';
      default: return '';
    }
  };

  // Get current input icon
  const getInputIcon = () => {
    if (isSignin) {
      return currentStep === 1 ? Mail : Lock;
    }
    
    switch(currentStep) {
      case 1: return User;
      case 2: return Mail;
      case 3: return Lock;
      case 4: return Lock;
      default: return User;
    }
  };

  // Email validation regex
  const validateEmail = (email) => {
    const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return re.test(String(email).toLowerCase());
  };

  // Username validation regex
  const validateUsername = (username) => {
    // Username must be alphabetical and max 10 characters
    const re = /^[a-zA-Z]{1,10}$/;
    return re.test(username);
  };

  // Validate current input step
  const validateCurrentStep = () => {
    const value = formData[getCurrentInputName()];
    
    if (!value) {
      toast.error(`${getCurrentLabel()} is required, { id: ${getCurrentLabel()}-required }`);
      return false;
    }

    if (isSignin) {
      if (currentStep === 1 && !validateEmail(value)) {
        toast.error('Please enter a valid email address', { id: 'invalid-email' });
        return false;
      }
      if (currentStep === 2 && value.length < 6) {
        toast.error('Password must be at least 6 characters long', { id: 'password-length' });
        return false;
      }
    } else {
      switch(currentStep) {
        case 1:
          if (!validateUsername(value)) {
            if (value.length > 10) {
              toast.error('Username must be at most 10 characters long', { id: 'username-length' });
            } else if (value.length < 1) {
              toast.error('Username is required', { id: 'username-required' });
            } else {
              toast.error('Username must contain only letters (a-z, A-Z)', { id: 'username-format' });
            }
            return false;
          }
          break;
        case 2:
          if (!validateEmail(value)) {
            toast.error('Please enter a valid email address', { id: 'invalid-email' });
            return false;
          }
          break;
        case 3:
          if (value.length < 6) {
            toast.error('Password must be at least 6 characters long', { id: 'password-length' });
            return false;
          }
          break;
        case 4:
          if (value !== formData.password) {
            toast.error('Passwords do not match', { id: 'password-mismatch' });
            return false;
          }
          break;
      }
    }

    return true;
  };

  // Handle next step or submission
  const handleNext = () => {
    if (validateCurrentStep()) {
      if (currentStep < totalSteps) {
        setCurrentStep(prev => prev + 1);
      } else {
        handleSubmit();
      }
    }
  };

  // Handle previous step
  const handlePrev = () => {
    if (currentStep > 1) {
      setCurrentStep(prev => prev - 1);
    }
  };

  // Submit authentication request
  const handleSubmit = async () => {
    try {
      // Encrypt password
      const encryptedPassword = encryptPassword(formData.password);
      
      if (!encryptedPassword) {
        console.error('Password encryption failed');
        return;
      }
  
      // Generate device token
      const token = await generateToken();
  
      // Prepare authentication payload
      const payload = isSignin 
        ? {
            auth: 'signin',
            email: formData.email.toLowerCase(),
            password: formData.password
          }
        : {
            auth: 'signup',
            username: formData.username,
            email: formData.email.toLowerCase(),
            password: encryptedPassword
          };
  
      console.log('Authentication payload:', payload);
      // Send authentication request
      const response = await authApi(payload);
      
      // Handle authentication response
      if (!isSignin) {
        // Signup successful
        toast.success('Account created successfully! \nPlease sign in.', { id: 'account-created' });
        setIsSignin(true);
        setCurrentStep(1);
        setFormData({
          username: '',
          email: formData.email.toLowerCase(),
          password: '',
          confirmPassword: ''
        });
      } else {
        // Signin successful
        const cookieOptions = { 
          expires: 7,
          path: '/' 
        };
  
        // Set authentication cookies
        setCookie('userEmail', response.email, cookieOptions);
        setCookie('username', response.username, cookieOptions);
        setCookie('deviceToken', token, cookieOptions);
        
        toast.success('Successfully signed in!', { id: 'signin-success' });
        console.log('Authentication response:', response);
        localStorage.setItem('activeTab', 'Server Configuration')
        navigate('/');
      }
    } catch (err) {
      toast.error(err.message || 'Authentication failed', { id: 'authentication-failed' });
    }
  };

  // Toggle between signin and signup modes
  const toggleMode = () => {
    setIsSignin(!isSignin);
    setCurrentStep(1);
    setShowPassword(false);
    setFormData({
      username: '',
      email: '',
      password: '',
      confirmPassword: ''
    });
    toast.dismiss();
  };

  const InputIcon = getInputIcon();

  return (
    <div className="min-h-svh bg-gradient-to-br from-black via-black/90 to-black flex items-center justify-center p-4">
      <ToastContainer />
      
      <div className="w-full max-w-md">
        {/* Heading */}
        <div className="text-center mb-8">
          <h2 className="text-3xl font-bold text-white mb-2">
            {isSignin ? 'Welcome Back!' : 'Join Us Today'}
          </h2>
        </div>

        {/* Step Indicators */}
        <div className="flex justify-center items-center gap-2 mb-8">
          {[...Array(totalSteps)].map((_, index) => (
            <div
              key={index}
              className={`h-1 ${index + 1 <= currentStep ? 'w-12 bg-white' : 'w-8 bg-gray-700'} 
                rounded-full transition-all duration-300 ease-in-out
                ${currentStep === index + 1 ? 'scale-110' : ''}`}
            />
          ))}
        </div>

        <div className="bg-black/20 backdrop-blur-xl p-8 rounded-2xl border border-gray-900/50 shadow-2xl">
          <form onSubmit={(e) => e.preventDefault()} className="space-y-6">
            <div className="space-y-2">
              <label htmlFor="stepInput" className="block text-sm font-medium text-gray-300">
                {getCurrentLabel()}
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <InputIcon className="h-5 w-5 text-gray-400" />
                </div>
                <input
                  id="stepInput"
                  ref={inputRef}
                  name={getCurrentInputName()}
                  type={getCurrentInputType()}
                  value={formData[getCurrentInputName()]}
                  onChange={handleInputChange}
                  className="block outline-none w-full pl-10 pr-12 py-3 rounded-xl bg-black/20 border-none text-white placeholder-gray-400 ring-1 ring-white/20 focus:ring-2 focus:ring-white/20 focus:border-transparent transition-all duration-200"
                  placeholder={getCurrentPlaceholder()}
                />
                {(isSignin ? currentStep === 2 : currentStep === 3 || currentStep === 4) && (
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  >
                    {showPassword ? (
                      <EyeOff className="h-5 w-5 text-gray-400 hover:text-gray-300" />
                    ) : (
                      <Eye className="h-5 w-5 text-gray-400 hover:text-gray-300" />
                    )}
                  </button>
                )}
              </div>
            </div>

            <div className="flex gap-3">
              {currentStep > 1 && (
                <button
                  type="button"
                  onClick={handlePrev}
                  className="flex-1 flex items-center justify-center gap-2 py-3 px-4 bg-gradient-to-l from-white/10 to-white/20 hover:from-white/20 hover:to-white/30 text-white font-medium rounded-xl transition-all duration-200 cursor-pointer"
                >
                  <ArrowLeft className="h-4 w-4" />
                  Back
                </button>
              )}
              
              <button
                type="button"
                onClick={handleNext}
                className="flex-1 flex items-center justify-center gap-2 py-3 px-4 bg-gradient-to-r from-white/10 to-white/20 hover:from-white/20 hover:to-white/30 text-white font-medium rounded-xl transition duration-200 cursor-pointer"
              >
                {currentStep === totalSteps ? (
                  isSignin ? 'Sign in' : 'Sign up'
                ) : (
                  <>
                    Next
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>
            <div className="text-center mt-6">
              <button
                type="button"
                onClick={toggleMode}
                className="text-sm cursor-pointer text-gray-400 hover:text-white transition-colors duration-200"
              >
                {isSignin
                  ? "Don't have an account? Sign up"
                  : 'Already have an account? Sign in'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Auth;
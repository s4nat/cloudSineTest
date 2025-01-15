// src/components/auth/LoginPage.jsx
import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { GoogleLogin } from '@react-oauth/google';
import { useAuth } from '../../hooks/useAuth';
import { jwtDecode } from 'jwt-decode'; // Changed from jwt_decode to jwtDecode

const LoginPage = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const handleGoogleSuccess = async (credentialResponse) => {
    try {
      // Decode the credential to get user info
      const decoded = jwtDecode(credentialResponse.credential);
      
      // Pass the credential to our login function
      await login(credentialResponse.credential, decoded);
      
      // After successful login, redirect
      const destination = location.state?.from?.pathname || '/';
      navigate(destination);
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-gray-900 to-gray-800">
      <div className="max-w-md w-full space-y-8 p-8 bg-gray-800/50 backdrop-blur-sm rounded-lg border border-gray-700">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
            Sign in to File Scanner
          </h2>
          <p className="mt-2 text-center text-gray-400">
            Use your Google account to continue
          </p>
        </div>
        <div className="mt-8 space-y-6">
          <div className="flex justify-center">
            <GoogleLogin
              onSuccess={handleGoogleSuccess}
              onError={() => {
                console.log('Login Failed');
              }}
              useOneTap
              theme="filled_black"
              shape="pill"
              size="large"
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
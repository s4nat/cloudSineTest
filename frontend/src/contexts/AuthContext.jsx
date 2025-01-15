import React, { createContext, useState, useCallback } from 'react';
import { authService } from '../services/auth';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const login = useCallback(async (credential, decodedUser) => {
    setLoading(true);
    setError(null);
    try {
      // Use authService to make the API call
      const data = await authService.googleLogin(credential, decodedUser);
      // Store user data and token
      setUser({
        id: data.user.id,
        email: data.user.email,
        name: data.user.name,
      });
      localStorage.setItem('token', data.token);
      
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    setUser(null);
    localStorage.removeItem('token');
  }, []);

  const value = {
    user,
    loading,
    error,
    login,
    logout,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export { AuthContext };
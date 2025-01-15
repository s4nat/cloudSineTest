import React from 'react';
import { render } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import { GoogleOAuthProvider } from '@react-oauth/google';
import { AuthProvider } from './contexts/AuthContext';
import App from './App';

// A basic smoke test just to ensure the app renders without crashing
test('renders without crashing', () => {
  render(
    <BrowserRouter>
      <GoogleOAuthProvider clientId="dummy-client-id">
        <AuthProvider>
          <App />
        </AuthProvider>
      </GoogleOAuthProvider>
    </BrowserRouter>
  );
});
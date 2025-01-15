import api from './api';

export const authService = {
  googleLogin: async (credential, userData) => {
    const response = await api.post('/auth/google', {
      credential,
      email: userData.email,
      name: userData.name,
    });
    return response.data;
  },
};
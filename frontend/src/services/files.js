import api from './api';

export const fileService = {
  uploadFile: async (file) => {
    try {
      const formData = new FormData();
      formData.append('file', file);
      const response = await api.post('/files/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      return response.data;
    } catch (error) {
      // If it's a duplicate file (409 Conflict), we want to pass this to the component
      if (error.response?.status === 409) {
        throw error;
      }
      throw new Error(error.response?.data?.message || 'Error uploading file');
    }
  },

  getFiles: async () => {
    try {
      const response = await api.get('/files');
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Error fetching files');
    }
  },

  getFileDetails: async (fileId) => {
    try {
      const response = await api.get(`/files/${fileId}`);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Error fetching file details');
    }
  },

  getScanResults: async (fileId) => {
    try {
      const response = await api.get(`/files/${fileId}/scan-results`);
      return response.data;
    } catch (error) {
      throw new Error(error.response?.data?.message || 'Error fetching scan results');
    }
  },
};
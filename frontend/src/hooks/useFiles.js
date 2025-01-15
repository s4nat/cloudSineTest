import { useState, useCallback } from 'react';
import { useAuth } from './useAuth';
import { fileService } from '../services/files';

export const useFiles = () => {
  const { user } = useAuth();
  const [files, setFiles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchFiles = useCallback(async () => {
    if (!user) return;
    
    setLoading(true);
    setError(null);
    try {
      const data = await fileService.getFiles();
      setFiles(data);
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [user]);

  const uploadFile = useCallback(async (file) => {
    if (!user) return;

    setLoading(true);
    setError(null);
    try {
      const data = await fileService.uploadFile(file);
      setFiles(prev => [...prev, data]);
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [user]);

  const scanFile = useCallback(async (fileId) => {
    if (!user) return;

    setLoading(true);
    setError(null);
    try {
      const data = await fileService.scanFile(fileId);
      setFiles(prev => 
        prev.map(file => 
          file.id === fileId 
            ? { ...file, status: 'Scanning' }
            : file
        )
      );
      return data;
    } catch (err) {
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [user]);

  return {
    files,
    loading,
    error,
    fetchFiles,
    uploadFile,
    scanFile
  };
};
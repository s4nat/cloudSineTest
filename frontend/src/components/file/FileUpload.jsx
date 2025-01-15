import React, { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useFiles } from '../../hooks/useFiles';
import { Upload, AlertCircle, CheckCircle, Search, Eye } from 'lucide-react';

const FileUpload = () => {
  const navigate = useNavigate();
  const { uploadFile } = useFiles();
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);
  const [uploadedFileId, setUploadedFileId] = useState(null);
  const [duplicate, setDuplicate] = useState(null);

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const handleUpload = useCallback(async (files) => {
    setUploading(true);
    setError(null);
    setSuccess(false);
    setDuplicate(null);

    try {
      const file = files[0];
      if (!file) throw new Error('No file selected');
      if (file.size > 50 * 1024 * 1024) throw new Error('File size must be less than 50MB');
      
      const response = await uploadFile(file).catch(err => {
        // Check if the error response indicates a duplicate file
        if (err.response?.status === 409) {
          setDuplicate(err.response.data);
          throw new Error('FILE_DUPLICATE'); // Custom error to handle differently
        }
        throw err;
      });
      
      setSuccess(true);
      setUploadedFileId(response.id);

    } catch (err) {
      if (err.message !== 'FILE_DUPLICATE') {
        setError(err.message);
      }
    } finally {
      setUploading(false);
      setDragActive(false);
    }
  }, [uploadFile]);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    const files = e.dataTransfer.files;
    handleUpload(files);
  }, [handleUpload]);

  const handleChange = useCallback((e) => {
    const files = e.target.files;
    handleUpload(files);
  }, [handleUpload]);

  const handleViewResults = useCallback(() => {
    navigate(`/files/${uploadedFileId}`);
  }
  , [navigate, uploadedFileId]);

  const viewDuplicateScanResults = useCallback(() => {
    if (duplicate?.file?.id) {
      navigate(`/files/${duplicate.file.id}`);
    }
  }, [duplicate, navigate]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 to-gray-800 flex flex-col items-center justify-center p-6">
      <div className="w-full max-w-2xl">
        <h2 className="text-3xl font-bold mb-8 text-center text-white">Upload File for Scanning</h2>

        {/* Upload Area */}
        <div
          className={`relative border-2 border-dashed rounded-lg p-12 text-center transition-all duration-200
            ${dragActive ? 'border-blue-400 bg-gray-800/50' : 'border-gray-600'}
            ${uploading ? 'opacity-50' : ''}
            hover:border-blue-400 bg-gray-800/30 backdrop-blur-sm`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <input
            type="file"
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
            onChange={handleChange}
            disabled={uploading}
          />
          
          <Upload className="mx-auto h-16 w-16 text-blue-400" />
          
          <p className="mt-6 text-xl font-medium text-white">
            {dragActive ? 'Drop your file here' : 'Drag & drop your file here'}
          </p>
          <p className="mt-2 text-gray-400">or click to browse</p>
          <p className="mt-2 text-sm text-gray-500">Maximum file size: 50MB</p>
        </div>

        {/* Status Messages */}
        {uploading && (
          <div className="mt-6 bg-gray-800/50 backdrop-blur-sm p-4 rounded-lg border border-gray-700">
            <div className="flex items-center justify-center text-blue-400 gap-2">
              <div className="animate-spin w-5 h-5 border-2 border-blue-400 border-t-transparent rounded-full"></div>
              <span>Uploading...</span>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-6 bg-red-900/30 backdrop-blur-sm p-4 rounded-lg border border-red-800/50 flex items-center gap-2">
            <AlertCircle className="h-5 w-5 text-red-400" />
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {success && (
          <div className="mt-6 space-y-4">
            <div className="bg-green-900/30 backdrop-blur-sm p-4 rounded-lg border border-green-800/50 flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-400" />
              <p className="text-green-400">File uploaded successfully!</p>
            </div>
            
            <button
              onClick={handleViewResults}
              className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-blue-500/10 text-blue-400 rounded-lg hover:bg-blue-500/20 transition-colors duration-200"
            >
              <Search size={18} />
              <span>View Scan Results</span>
            </button>
          </div>
        )}

        {duplicate && (
                  <div className="mt-6 bg-blue-900/30 backdrop-blur-sm p-4 rounded-lg border border-blue-800/50">
                    <div className="flex items-center gap-2 mb-3">
                      <AlertCircle className="h-5 w-5 text-blue-400" />
                      <p className="text-blue-400">This file has already been uploaded</p>
                    </div>
                    <button
                      onClick={viewDuplicateScanResults}
                      className="flex items-center gap-2 px-4 py-2 bg-blue-500/20 rounded-lg text-blue-400 hover:bg-blue-500/30 transition-colors"
                    >
                      <Eye size={18} />
                      <span>View Scan Results</span>
                    </button>
                  </div>
                )}
      </div>
    </div>
  );
};

export default FileUpload;
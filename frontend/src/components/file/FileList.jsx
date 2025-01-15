import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useFiles } from '../../hooks/useFiles';
import { FileText, AlertCircle, Shield, Clock } from 'lucide-react';

const FileList = () => {
  const { files, loading, error, fetchFiles } = useFiles();
  const navigate = useNavigate();

  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  const getStatusColor = (status) => {
    switch (status) {
      case 'Complete':
        return 'text-green-400';
      case 'Scanning':
        return 'text-blue-400';
      case 'Not Scanned':
        return 'text-gray-400';
      default:
        return 'text-gray-400';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'Complete':
        return Shield;
      case 'Scanning':
        return Clock;
      default:
        return FileText;
    }
  };

  const formatDateTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin w-8 h-8 border-2 border-blue-400 border-t-transparent rounded-full"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/30 backdrop-blur-sm p-4 rounded-lg border border-red-800/50 flex items-center gap-2">
        <AlertCircle className="h-5 w-5 text-red-400" />
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h2 className="text-2xl font-bold text-white">Uploaded Files</h2>
      
      <div className="grid gap-4">
        {files.length === 0 ? (
          <div className="text-center py-12 bg-gray-800/30 rounded-lg border border-gray-700">
            <FileText className="mx-auto h-12 w-12 text-gray-500 mb-3" />
            <p className="text-gray-400">No files uploaded yet</p>
          </div>
        ) : (
          files.map((file) => {
            const StatusIcon = getStatusIcon(file.status);
            return (
              <div
                key={file.id}
                onClick={() => navigate(`/files/${file.id}`)}
                className="group bg-gray-800/30 backdrop-blur-sm border border-gray-700 rounded-lg p-4 hover:bg-gray-800/50 transition-all duration-200 cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <StatusIcon className={`h-5 w-5 ${getStatusColor(file.status)}`} />
                    <div>
                      <h3 className="text-white font-medium group-hover:text-blue-400 transition-colors">
                        {file.file_name}
                      </h3>
                      <p className="text-sm text-gray-400">
                        {formatDateTime(file.created_at)}
                      </p>
                    </div>
                  </div>
                  <span className={`text-sm ${getStatusColor(file.status)}`}>
                    {file.status}
                  </span>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default FileList;
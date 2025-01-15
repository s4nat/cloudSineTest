import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useFiles } from '../../hooks/useFiles';
import { fileService } from '../../services/files';
import { 
  Shield, AlertCircle, ArrowLeft, FileText, Calendar, 
  HardDrive, Activity, Hash, Clock, XCircle, CheckCircle,
  AlertTriangle, HelpCircle, Ban
} from 'lucide-react';

const StatCard = ({ label, value, icon: Icon, variant }) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'danger':
        return 'bg-red-900/20 border-red-700/30 text-red-400';
      case 'warning':
        return 'bg-yellow-900/20 border-yellow-700/30 text-yellow-400';
      case 'success':
        return 'bg-green-900/20 border-green-700/30 text-green-400';
      default:
        return 'bg-gray-800/30 border-gray-700 text-gray-400';
    }
  };

  return (
    <div className={`p-4 rounded-lg border ${getVariantStyles()}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm">{label}</span>
        <Icon className="h-5 w-5" />
      </div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
};

const FileDetails = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { files, loading: filesLoading, fetchFiles } = useFiles();
  const [file, setFile] = useState(null);
  const [scanResults, setScanResults] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // First useEffect to fetch the files if they're not already loaded
  useEffect(() => {
    fetchFiles();
  }, [fetchFiles]);

  useEffect(() => {
    const loadFileAndScanResults = async () => {
      try {
        setLoading(true);
        setError(null);

        // Fetch both file details and scan results concurrently
        const [fileDetails, scanResults] = await Promise.all([
          fileService.getFileDetails(id),
          fileService.getScanResults(id)
        ]);

        setFile(fileDetails);
        setScanResults(scanResults);
      } catch (err) {
        setError(err.message);
        console.error('Error loading file details:', err);
      } finally {
        setLoading(false);
      }
    };

    if (id && files.length > 0) {
      loadFileAndScanResults();
    }
  }, [id, files]);

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

  // Only show malicious and suspicious results
  const getFilteredResults = () => {
    if (!scanResults?.data?.attributes?.results) return [];
    
    return Object.entries(scanResults.data.attributes.results)
      .filter(([_, result]) => 
        result.category === 'malicious' || result.category === 'suspicious'
      )
      .map(([engine, result]) => ({
        engine_name: result.engine_name,
        category: result.category,
        method: result.method,
        result: result.result
      }));
  };

  if (loading || filesLoading) {
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

  if (!file) {
    return (
      <div className="bg-yellow-900/30 backdrop-blur-sm p-4 rounded-lg border border-yellow-800/50 flex items-center gap-2">
        <AlertCircle className="h-5 w-5 text-yellow-400" />
        <p className="text-yellow-400">File not found</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/files')}
          className="flex items-center gap-2 text-gray-400 hover:text-white transition-colors"
        >
          <ArrowLeft size={20} />
          <span>Back to Files</span>
        </button>
      </div>

      {/* File Info */}
      <div className="bg-gray-800/30 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
        <div className="flex items-start justify-between mb-6">
          <div className="flex items-center gap-3">
            <FileText className="h-8 w-8 text-blue-400" />
            <div>
              <h1 className="text-2xl font-bold text-white">{file.file_name}</h1>
              <p className="text-gray-400">
                Uploaded on {formatDateTime(file.created_at)}
              </p>
            </div>
          </div>
          <div className={`px-4 py-2 rounded-full border ${
            file.status === 'Complete' ? 'border-green-500/30 text-green-400' :
            file.status === 'Scanning' ? 'border-blue-500/30 text-blue-400' :
            'border-gray-600 text-gray-400'
          }`}>
            {file.status}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-6">
          <div className="space-y-4">
            <h3 className="text-lg font-medium text-white">File Information</h3>
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-gray-400">
                <HardDrive size={16} />
                <span>Size: {(file.file_size / 1024 / 1024).toFixed(2)} MB</span>
              </div>
              <div className="flex items-center gap-2 text-gray-400">
                <FileText size={16} />
                <span>Type: {file.file_type}</span>
              </div>
              <div className="flex items-center gap-2 text-gray-400">
                <Calendar size={16} />
                <span>Created: {formatDateTime(file.created_at)}</span>
              </div>
            </div>
          </div>

          {scanResults && (
            <div className="space-y-4">
              <h3 className="text-lg font-medium text-white">Scan Results</h3>
              <div className="space-y-2">
                <div className="flex items-center gap-2 text-gray-400">
                  <Shield size={16} />
                  <span>Status: {scanResults.data?.attributes?.status || 'Unknown'}</span>
                </div>
                <div className="flex items-center gap-2 text-gray-400">
                  <Activity size={16} />
                  <span className="truncate">Analysis ID: {file.analysis_id}</span>
                </div>
              </div>
              <div className="flex items-center gap-2 text-gray-400">
                <Hash size={16} />
                <span className="truncate">SHA256: {file.sha256_hash.String}</span>
                </div>
            </div>
          )}
        </div>
      </div>

      {/* Analysis Stats Section */}
      {scanResults && scanResults.data?.attributes?.stats && (
        <div className="bg-gray-800/30 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
          <h3 className="text-lg font-medium text-white mb-4">Analysis Statistics</h3>
          <div className="grid grid-cols-4 gap-4">
            <StatCard 
              label="Malicious" 
              value={scanResults.data.attributes.stats.malicious}
              icon={Shield}
              variant="danger"
            />
            <StatCard 
              label="Suspicious" 
              value={scanResults.data.attributes.stats.suspicious}
              icon={AlertTriangle}
              variant="warning"
            />
            <StatCard 
              label="Harmless" 
              value={scanResults.data.attributes.stats.harmless}
              icon={CheckCircle}
              variant="success"
            />
            <StatCard 
              label="Undetected" 
              value={scanResults.data.attributes.stats.undetected}
              icon={HelpCircle}
            />
            <StatCard 
              label="Timeout" 
              value={scanResults.data.attributes.stats['confirmed-timeout']}
              icon={Clock}
            />
            <StatCard 
              label="Failure" 
              value={scanResults.data.attributes.stats.failure}
              icon={XCircle}
            />
            <StatCard 
              label="Unsupported" 
              value={scanResults.data.attributes.stats['type-unsupported']}
              icon={Ban}
            />
          </div>
        </div>
      )}

      {/* Threat Results Section */}
      {scanResults && scanResults.data?.attributes?.results && (
        <div className="bg-gray-800/30 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
          <h3 className="text-lg font-medium text-white mb-4">Threat Detections</h3>
          <div className="space-y-4">
            {getFilteredResults().map((result, index) => (
              <div 
                key={index}
                className={`p-4 rounded-lg border ${
                  result.category === 'malicious' 
                    ? 'bg-red-900/20 border-red-700/30' 
                    : 'bg-yellow-900/20 border-yellow-700/30'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-white">{result.engine_name}</span>
                  <span className={`px-2 py-1 rounded-full text-sm ${
                    result.category === 'malicious'
                      ? 'bg-red-900/30 text-red-400'
                      : 'bg-yellow-900/30 text-yellow-400'
                  }`}>
                    {result.category}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="text-gray-400">
                    <span className="text-gray-500">Detection Method:</span> {result.method}
                  </div>
                  <div className="text-gray-400">
                    <span className="text-gray-500">Result:</span> {result.result}
                  </div>
                </div>
              </div>
            ))}
            {getFilteredResults().length === 0 && (
              <div className="text-center py-8 text-gray-400">
                No threats detected
              </div>
            )}
          </div>
        </div>
      )}

      {/* Raw Analysis Data */}
      {scanResults && (
        <div className="bg-gray-800/30 backdrop-blur-sm border border-gray-700 rounded-lg p-6">
          <h3 className="text-lg font-medium text-white mb-4">Detailed Analysis</h3>
          <pre className="bg-gray-900/50 p-4 rounded-lg overflow-x-auto text-gray-300">
            {JSON.stringify(scanResults, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

export default FileDetails;
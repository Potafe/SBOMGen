'use client';

import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { apiClient } from '@/lib/api';
import { RepositoryUpload, ScanResponse } from '@/types/scan';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';

const uploadSchema = z.object({
  repo_url: z.string().url('Enter a valid GitHub repository URL'),
  github_token: z.string().optional(),
});

interface UploadFormProps {
  onUploadSuccess: (response: ScanResponse) => void;
}

export function UploadForm({ onUploadSuccess }: UploadFormProps) {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { register, handleSubmit, formState: { errors }, reset } = useForm<RepositoryUpload>({
    resolver: zodResolver(uploadSchema),
  });

  const onSubmit = async (data: RepositoryUpload) => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await apiClient.uploadRepository(data);
      onUploadSuccess(response);
      reset();
    } catch (err) {
      setError('Failed to upload repository. Please try again.');
      console.error('Upload error:', err);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      <div>
        <Label htmlFor="repo_url">GitHub Repository URL</Label>
        <Input
          id="repo_url"
          type="url"
          placeholder="https://github.com/username/repo"
          {...register('repo_url')}
          className={errors.repo_url ? 'border-red-500' : ''}
        />
        {errors.repo_url && (
          <p className="text-red-500 text-sm mt-1">{errors.repo_url.message}</p>
        )}
      </div>
      
      <div>
        <Label htmlFor="github_token">GitHub Token (Optional - for private repos)</Label>
        <Input
          id="github_token"
          type="password"
          placeholder="ghp_..."
          {...register('github_token')}
        />
        <p className="text-sm text-gray-500 mt-1">
          Required for private repositories. Create a PAT with repo access.
        </p>
      </div>
      
      {error && (
        <p className="text-red-500 text-sm">{error}</p>
      )}
      
      <Button type="submit" disabled={isLoading} className="w-full">
        {isLoading ? 'Uploading...' : 'Upload Repository'}
      </Button>
    </form>
  );
}
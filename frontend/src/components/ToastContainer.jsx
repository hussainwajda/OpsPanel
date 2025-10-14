import { Toaster } from 'react-hot-toast';

const ToastContainer = () => {
  return (
    <Toaster
      position="top-center"
      reverseOrder={false}
      gutter={8}
      toastOptions={{
        id: (t) => t.message,
        className: 'select-none',
        duration: 3000,
        style: {
          maxWidth: '350px',
          padding: '16px',
          borderRadius: '12px',
          background: 'rgba(0, 0, 0, 0.8)',
          backdropFilter: 'blur(10px)',
          color: '#fff',
          boxShadow: '0 8px 16px rgba(0, 0, 0, 0.2)',
        },
        success: {
          style: {
            background: 'rgba(0, 0, 0, 0.8)',
            backdropFilter: 'blur(10px)',
            color: '#fff',
          },
          iconTheme: {
            primary: '#4ade80',
            secondary: 'rgba(0, 0, 0, 0.8)',
          },
        },
        error: {
          style: {
            background: 'rgba(0, 0, 0, 0.8)',
            backdropFilter: 'blur(10px)',
            color: '#fff',
          },
          iconTheme: {
            primary: '#f87171',
            secondary: 'rgba(0, 0, 0, 0.8)',
          },
          duration: 2000,
        },
      }}
    />
  );
};

export default ToastContainer;
import React from 'react';
import { Scrollbars } from 'react-custom-scrollbars-2';

const CustomScrollbar = ({ children, className, ...props }) => {
  // Custom scrollbar thumb styles
  const renderThumb = ({ style, ...props }) => {
    const thumbStyle = {
      backgroundColor: 'rgba(255, 255, 255, 0.3)',
      borderRadius: '4px',
      width: '6px',
    };
    return <div style={{ ...style, ...thumbStyle }} {...props} />;
  };

  // Custom scrollbar track styles
  const renderTrack = ({ style, ...props }) => {
    const trackStyle = {
      backgroundColor: 'rgba(0, 0, 0, 0.2)',
      borderRadius: '4px',
      width: '6px',
      right: '2px',
      bottom: '2px',
      top: '2px',
      position: 'absolute',
    };
    return <div style={{ ...style, ...trackStyle }} {...props} />;
  };

  return (
    <Scrollbars
      renderThumbVertical={renderThumb}
      renderTrackVertical={renderTrack}
      className={className}
      autoHide
      autoHideTimeout={1000}
      autoHideDuration={200}
      {...props}
    >
      {children}
    </Scrollbars>
  );
};

export default CustomScrollbar;
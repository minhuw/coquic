import localFont from 'next/font/local';

export const hostGrotesk = localFont({
  src: [
    {
      path: '../assets/fonts/host-grotesk/HostGrotesk-Regular.woff2',
      weight: '400',
      style: 'normal',
    },
    {
      path: '../assets/fonts/host-grotesk/HostGrotesk-Medium.woff2',
      weight: '500',
      style: 'normal',
    },
    {
      path: '../assets/fonts/host-grotesk/HostGrotesk-SemiBold.woff2',
      weight: '600',
      style: 'normal',
    },
    {
      path: '../assets/fonts/host-grotesk/HostGrotesk-Bold.woff2',
      weight: '700',
      style: 'normal',
    },
  ],
  variable: '--font-host-grotesk',
  display: 'swap',
});

export const googleSansCode = localFont({
  src: [
    {
      path: '../assets/fonts/google-sans-code/GoogleSansCode[MONO,wght].ttf',
      weight: '400 700',
      style: 'normal',
    },
  ],
  variable: '--font-google-sans-code',
  display: 'swap',
});

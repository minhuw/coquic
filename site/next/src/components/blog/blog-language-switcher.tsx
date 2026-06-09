'use client';

import type { ReactNode } from 'react';
import { createContext, useContext, useState } from 'react';

type BlogLanguage = 'en' | 'zh';

type BlogLanguageProviderProps = {
  children: ReactNode;
};

type BlogLanguagePanelProps = {
  children: ReactNode;
  language: BlogLanguage;
};

const languages: { label: string; value: BlogLanguage }[] = [
  { label: 'English', value: 'en' },
  { label: '中文', value: 'zh' },
];

const BlogLanguageContext = createContext<BlogLanguage>('en');
const BlogLanguageUpdateContext = createContext<(language: BlogLanguage) => void>(() => {});

export function BlogLanguageProvider({ children }: BlogLanguageProviderProps) {
  const [language, setLanguage] = useState<BlogLanguage>('en');

  return (
    <section className="blog-language-shell" data-blog-language={language}>
      <BlogLanguageContext.Provider value={language}>
        <BlogLanguageUpdateContext.Provider value={setLanguage}>{children}</BlogLanguageUpdateContext.Provider>
      </BlogLanguageContext.Provider>
    </section>
  );
}

export function BlogLanguageTabs() {
  const language = useContext(BlogLanguageContext);
  const setLanguage = useContext(BlogLanguageUpdateContext);

  return (
    <div className="blog-language-tabs" role="group" aria-label="Select article language">
      {languages.map((item) => (
        <button
          aria-pressed={language === item.value}
          className="blog-language-tab"
          key={item.value}
          onClick={() => setLanguage(item.value)}
          type="button"
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

export function BlogLanguagePanel({ children, language }: BlogLanguagePanelProps) {
  const activeLanguage = useContext(BlogLanguageContext);
  const active = activeLanguage === language;

  return (
    <div
      aria-hidden={!active}
      className="blog-language-panel"
      data-blog-language-panel={language}
      hidden={!active}
      lang={language === 'zh' ? 'zh-CN' : 'en'}
    >
      {children}
    </div>
  );
}

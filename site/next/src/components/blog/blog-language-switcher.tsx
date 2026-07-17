'use client';

import type { ReactNode } from 'react';
import { createContext, useContext, useState } from 'react';

import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';

import styles from './blog.module.css';

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
const BlogLanguageTabsContext = createContext(false);

export function BlogLanguageProvider({ children }: BlogLanguageProviderProps) {
  const [language, setLanguage] = useState<BlogLanguage>('en');
  const handleLanguageChange = (value: string) => {
    if (value === 'en' || value === 'zh') setLanguage(value);
  };

  return (
    <section className={styles.languageShell} data-blog-language={language}>
      <BlogLanguageContext.Provider value={language}>
        <BlogLanguageTabsContext.Provider value>
          <Tabs className={styles.languageRoot} value={language} onValueChange={handleLanguageChange}>
            {children}
          </Tabs>
        </BlogLanguageTabsContext.Provider>
      </BlogLanguageContext.Provider>
    </section>
  );
}

export function BlogLanguageTabs() {
  return (
    <TabsList className={styles.languageTabs} aria-label="Article language">
      {languages.map((item) => (
        <TabsTrigger
          className={styles.languageTab}
          key={item.value}
          value={item.value}
        >
          {item.label}
        </TabsTrigger>
      ))}
    </TabsList>
  );
}

export function BlogLanguagePanel({ children, language }: BlogLanguagePanelProps) {
  const active = useContext(BlogLanguageContext) === language;
  const insideTabs = useContext(BlogLanguageTabsContext);
  const panelProps = {
    'aria-hidden': !active,
    className: cn(styles.languagePanel, 'blog-language-panel'),
    'data-blog-language-panel': language,
    hidden: !active,
    lang: language === 'zh' ? 'zh-CN' : 'en',
  } as const;

  if (!insideTabs) return <div {...panelProps}>{children}</div>;

  return (
    <TabsContent
      {...panelProps}
      forceMount
      value={language}
    >
      {children}
    </TabsContent>
  );
}

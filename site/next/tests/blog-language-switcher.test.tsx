import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import {
  BlogLanguagePanel,
  BlogLanguageProvider,
  BlogLanguageTabs,
} from '@/components/blog/blog-language-switcher';

afterEach(cleanup);

function renderLanguageFixture() {
  return render(
    <BlogLanguageProvider>
      <BlogLanguageTabs />
      <BlogLanguagePanel language="en">English article content</BlogLanguagePanel>
      <BlogLanguagePanel language="zh">中文文章内容</BlogLanguagePanel>
    </BlogLanguageProvider>,
  );
}

describe('blog language characterization', () => {
  it('defaults to English with one selected tab and linked language panels', () => {
    renderLanguageFixture();

    const tablist = screen.getByRole('tablist', { name: 'Article language' });
    const english = screen.getByRole('tab', { name: 'English' });
    const chinese = screen.getByRole('tab', { name: '中文' });
    const englishPanel = screen.getByText('English article content').closest('[data-blog-language-panel]');
    const chinesePanel = screen.getByText('中文文章内容').closest('[data-blog-language-panel]');

    expect(tablist).toContainElement(english);
    expect(tablist).toContainElement(chinese);
    expect(english).toHaveAttribute('aria-selected', 'true');
    expect(chinese).toHaveAttribute('aria-selected', 'false');
    expect(tablist).toHaveAttribute('tabindex', '0');
    expect(screen.getByText('English article content')).toBeVisible();
    expect(screen.getByText('中文文章内容')).not.toBeVisible();
    expect(englishPanel).toHaveAttribute('role', 'tabpanel');
    expect(englishPanel).toHaveAttribute('lang', 'en');
    expect(chinesePanel).toHaveAttribute('lang', 'zh-CN');
    expect(englishPanel).toHaveAttribute('aria-labelledby', english.id);
    expect(chinesePanel).toHaveAttribute('aria-labelledby', chinese.id);
    expect(chinesePanel).toHaveAttribute('hidden');
    expect(chinesePanel).toHaveTextContent('中文文章内容');
  });

  it('activates Chinese immediately while retaining hidden English content', () => {
    renderLanguageFixture();
    const english = screen.getByRole('tab', { name: 'English' });
    const chinese = screen.getByRole('tab', { name: '中文' });
    const englishPanel = screen.getByText('English article content').closest('[data-blog-language-panel]');
    const chinesePanel = screen.getByText('中文文章内容').closest('[data-blog-language-panel]');

    fireEvent.mouseDown(chinese, { button: 0, ctrlKey: false });

    expect(english).toHaveAttribute('aria-selected', 'false');
    expect(chinese).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByText('English article content')).not.toBeVisible();
    expect(screen.getByText('中文文章内容')).toBeVisible();
    expect(englishPanel).toHaveAttribute('hidden');
    expect(chinesePanel).not.toHaveAttribute('hidden');
    expect(englishPanel).toHaveTextContent('English article content');
  });

  it('supports roving Left/Right/Home/End focus with immediate activation', async () => {
    renderLanguageFixture();
    const english = screen.getByRole('tab', { name: 'English' });
    const chinese = screen.getByRole('tab', { name: '中文' });

    english.focus();
    fireEvent.keyDown(english, { key: 'ArrowRight' });
    await waitFor(() => expect(chinese).toHaveFocus());
    expect(chinese).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(chinese, { key: 'Home' });
    await waitFor(() => expect(english).toHaveFocus());
    expect(english).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(english, { key: 'End' });
    await waitFor(() => expect(chinese).toHaveFocus());
    expect(chinese).toHaveAttribute('aria-selected', 'true');

    fireEvent.keyDown(chinese, { key: 'ArrowLeft' });
    await waitFor(() => expect(english).toHaveFocus());
    expect(english).toHaveAttribute('aria-selected', 'true');
  });
});

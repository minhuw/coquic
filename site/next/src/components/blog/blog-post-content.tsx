import { compileMDX } from 'next-mdx-remote/rsc';
import remarkGfm from 'remark-gfm';

import { BlogLanguagePanel } from '@/components/blog/blog-language-switcher';
import { Markdown } from '@/components/docs/markdown';
import { hrefForBlogLink, type BlogPost } from '@/lib/blog';

type BlogPostContentProps = {
  post: BlogPost;
};

export async function BlogPostContent({ post }: BlogPostContentProps) {
  if (post.format === 'mdx') {
    const { content } = await compileMDX({
      source: post.markdown,
      options: {
        mdxOptions: {
          remarkPlugins: [remarkGfm],
        },
        parseFrontmatter: true,
      },
      components: {
        BlogLanguagePanel,
      },
    });

    return <div className="docs-markdown">{content}</div>;
  }

  return (
    <Markdown
      markdown={post.markdown}
      currentSlug={[post.slug]}
      skipFirstH1
      resolveHref={hrefForBlogLink}
    />
  );
}

const repositoryApi = "https://api.github.com/repos/minhuw/coquic";

export async function getGitHubStars(): Promise<number | null> {
  try {
    const response = await fetch(repositoryApi, {
      headers: {
        Accept: "application/vnd.github+json",
      },
      next: { revalidate: 60 * 60 },
    });

    if (!response.ok) return null;

    const repository: unknown = await response.json();
    if (
      typeof repository !== "object" ||
      repository === null ||
      !("stargazers_count" in repository) ||
      typeof repository.stargazers_count !== "number"
    ) {
      return null;
    }

    return repository.stargazers_count;
  } catch {
    return null;
  }
}

export const maskApiKey = (apiKey: string): string => {
    if (!apiKey || apiKey.length < 12) return '***';
    return `${apiKey.slice(0, 8)}***${apiKey.slice(-4)}`;
};
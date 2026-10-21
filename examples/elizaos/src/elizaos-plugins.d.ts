// @elizaos/plugin-bootstrap 1.7.2 ships no .d.ts, and @elizaos/plugin-sql 1.7.2's
// "exports" point at type files that are not in the tarball.
declare module "@elizaos/plugin-bootstrap" {
  const plugin: import("@elizaos/core").Plugin;
  export default plugin;
}
declare module "@elizaos/plugin-sql" {
  const plugin: import("@elizaos/core").Plugin;
  export default plugin;
  export function createDatabaseAdapter(
    config: { dataDir?: string; postgresUrl?: string },
    agentId: import("@elizaos/core").UUID,
  ): import("@elizaos/core").IDatabaseAdapter & { getDatabase(): unknown };
  export class DatabaseMigrationService {
    initializeWithDatabase(db: unknown): Promise<void>;
    discoverAndRegisterPluginSchemas(plugins: import("@elizaos/core").Plugin[]): void;
    runAllPluginMigrations(): Promise<void>;
  }
}

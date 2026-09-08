import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { PlaneApiError, type PlaneClient } from "./plane";

const pageQuerySchema = z.object({
	cursor: z.string().max(500).optional(),
	per_page: z.number().int().min(1).max(100).optional(),
	order_by: z.string().max(100).optional(),
});

const projectEntitySchema = pageQuerySchema.extend({
	action: z.enum(["list", "retrieve"]),
	project_id: z.string().uuid().optional(),
});

const workItemFields = {
	name: z.string().min(1).max(255).optional(),
	description_html: z.string().max(200_000).optional(),
	priority: z.enum(["urgent", "high", "medium", "low", "none"]).optional(),
	assignees: z.array(z.string().uuid()).max(100).optional(),
	labels: z.array(z.string().uuid()).max(100).optional(),
	state: z.string().uuid().optional(),
	start_date: z.string().date().optional(),
	target_date: z.string().date().optional(),
	parent: z.string().uuid().nullable().optional(),
	point: z.number().int().min(0).max(100).nullable().optional(),
};

type PlaneResult = { data: unknown; status: number };

function required(value: string | undefined, name: string): string {
	if (!value) throw new Error(`${name} is required for this action`);
	return value;
}

function compact(value: Record<string, unknown>): Record<string, unknown> {
	return Object.fromEntries(
		Object.entries(value).filter(([, field]) => field !== undefined),
	);
}

function queryFrom(input: {
	cursor?: string;
	per_page?: number;
	order_by?: string;
}): Record<string, unknown> {
	return compact({
		cursor: input.cursor,
		per_page: input.per_page,
		order_by: input.order_by,
	});
}

function toolOutput(data: unknown) {
	const structuredContent = { result: data };
	return {
		content: [
			{ type: "text" as const, text: JSON.stringify(structuredContent) },
		],
		structuredContent,
	};
}

async function runTool(
	subjectHash: string,
	tool: string,
	operation: () => Promise<PlaneResult>,
) {
	const started = Date.now();
	try {
		const result = await operation();
		console.log(
			JSON.stringify({
				event: "plane_mcp_tool",
				subject: subjectHash,
				tool,
				result: "ok",
				duration_ms: Date.now() - started,
				plane_status: result.status,
			}),
		);
		return toolOutput(result.data);
	} catch (error) {
		const status = error instanceof PlaneApiError ? error.status : 0;
		console.log(
			JSON.stringify({
				event: "plane_mcp_tool",
				subject: subjectHash,
				tool,
				result: "error",
				duration_ms: Date.now() - started,
				plane_status: status,
			}),
		);
		return {
			content: [
				{
					type: "text" as const,
					text:
						status === 401 || status === 403
							? "Plane credential is invalid or no longer authorized. Update it at /mcp/setup."
							: "Plane request failed.",
				},
			],
			isError: true,
		};
	}
}

export function createPlaneMcpServer(
	client: PlaneClient,
	accessSubjectHash: string,
): McpServer {
	const server = new McpServer({
		name: "RAYVEN Plane CE",
		version: "0.1.0",
	});

	server.registerTool(
		"plane_me",
		{
			description:
				"Return the current Plane user for the registered personal token.",
			inputSchema: z.object({}),
			annotations: { readOnlyHint: true, destructiveHint: false },
		},
		async () =>
			runTool(accessSubjectHash, "plane_me", () =>
				client.request("GET", ["users", "me"]),
			),
	);

	server.registerTool(
		"plane_project",
		{
			description: "List or retrieve projects in the fixed rayven workspace.",
			inputSchema: projectEntitySchema,
			annotations: { readOnlyHint: true, destructiveHint: false },
		},
		async (input) =>
			runTool(accessSubjectHash, "plane_project", () =>
				input.action === "list"
					? client.request("GET", client.workspacePath("projects"), {
							query: queryFrom(input),
						})
					: client.request(
							"GET",
							client.workspacePath(
								"projects",
								required(input.project_id, "project_id"),
							),
						),
			),
	);

	server.registerTool(
		"plane_member",
		{
			description:
				"List workspace or project members in the fixed rayven workspace.",
			inputSchema: pageQuerySchema.extend({
				scope: z.enum(["workspace", "project"]),
				project_id: z.string().uuid().optional(),
			}),
			annotations: { readOnlyHint: true, destructiveHint: false },
		},
		async (input) =>
			runTool(accessSubjectHash, "plane_member", () =>
				client.request(
					"GET",
					input.scope === "workspace"
						? client.workspacePath("members")
						: client.workspacePath(
								"projects",
								required(input.project_id, "project_id"),
								"members",
							),
					{ query: queryFrom(input) },
				),
			),
	);

	for (const resource of ["states", "labels", "cycles", "modules"] as const) {
		const singular = resource.slice(0, -1);
		const idName = `${singular}_id`;
		server.registerTool(
			`plane_${singular}`,
			{
				description: `List or retrieve ${resource} for a Plane project.`,
				inputSchema: pageQuerySchema.extend({
					action: z.enum(["list", "retrieve"]),
					project_id: z.string().uuid(),
					resource_id: z.string().uuid().optional().describe(idName),
				}),
				annotations: { readOnlyHint: true, destructiveHint: false },
			},
			async (input) =>
				runTool(accessSubjectHash, `plane_${singular}`, () =>
					client.request(
						"GET",
						input.action === "list"
							? client.workspacePath("projects", input.project_id, resource)
							: client.workspacePath(
									"projects",
									input.project_id,
									resource,
									required(input.resource_id, idName),
								),
						input.action === "list" ? { query: queryFrom(input) } : {},
					),
				),
		);
	}

	server.registerTool(
		"plane_intake",
		{
			description: "List or retrieve intake work items for a Plane project.",
			inputSchema: pageQuerySchema.extend({
				action: z.enum(["list", "retrieve"]),
				project_id: z.string().uuid(),
				work_item_id: z.string().uuid().optional(),
			}),
			annotations: { readOnlyHint: true, destructiveHint: false },
		},
		async (input) =>
			runTool(accessSubjectHash, "plane_intake", () =>
				client.request(
					"GET",
					input.action === "list"
						? client.workspacePath(
								"projects",
								input.project_id,
								"intake-issues",
							)
						: client.workspacePath(
								"projects",
								input.project_id,
								"intake-issues",
								required(input.work_item_id, "work_item_id"),
							),
					input.action === "list" ? { query: queryFrom(input) } : {},
				),
			),
	);

	server.registerTool(
		"plane_workitem",
		{
			description:
				"List, retrieve, search, create, or update work items. Delete and archive actions are not exposed.",
			inputSchema: pageQuerySchema.extend({
				action: z.enum(["list", "retrieve", "search", "create", "update"]),
				project_id: z.string().uuid().optional(),
				work_item_id: z.string().uuid().optional(),
				query: z.string().min(1).max(500).optional(),
				data: z.object(workItemFields).optional(),
			}),
			annotations: { destructiveHint: false },
		},
		async (input) => {
			const projectId = input.project_id;
			const base = () =>
				client.workspacePath(
					"projects",
					required(projectId, "project_id"),
					"work-items",
				);
			return runTool(accessSubjectHash, "plane_workitem", () => {
				switch (input.action) {
					case "list":
						return client.request("GET", base(), { query: queryFrom(input) });
					case "retrieve":
						return client.request("GET", [
							...base(),
							required(input.work_item_id, "work_item_id"),
						]);
					case "search":
						return client.request(
							"GET",
							client.workspacePath("work-items", "search"),
							{
								query: { search: required(input.query, "query") },
							},
						);
					case "create": {
						const data = compact(input.data ?? {});
						if (typeof data.name !== "string") {
							throw new Error("data.name is required for create");
						}
						return client.request("POST", base(), { body: data });
					}
					case "update":
						return client.request(
							"PATCH",
							[...base(), required(input.work_item_id, "work_item_id")],
							{ body: compact(input.data ?? {}) },
						);
				}
			});
		},
	);

	return server;
}

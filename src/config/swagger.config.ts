import fs from 'fs';
import path from 'path';
import swaggerJsdoc from 'swagger-jsdoc';

/** In Docker / production only compiled JS is present; swagger-jsdoc must scan dist/. */
const swaggerApiGlobs = fs.existsSync(
    path.join(process.cwd(), 'src', 'routes', 'v1', 'auth.routes.ts'),
)
    ? ['./src/routes/v1/*.ts', './src/controllers/*.ts']
    : ['./dist/routes/v1/*.js', './dist/controllers/*.js'];

const options: swaggerJsdoc.Options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Auth as a Service API',
            version: '1.0.0',
            description: 'An authentication service with multi-application support, OAuth 2.0, and 2FA/MFA capabilities.',
            contact: {
                name: 'API Support',
                email: 'patrickrakotoharilalao@gmail.com',
            },
        },
        servers: [
            {
                url: 'http://localhost:3001/api/v1',
                description: 'Development server',
            }
        ],
        components: {
            securitySchemes: {
                ApiKeyAuth: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'x-api-key',
                    description: 'Application API Key',
                },
                BearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                    description: 'JWT Access Token',
                },
            },
        },
    },
    apis: swaggerApiGlobs,
};

export const swaggerSpec = swaggerJsdoc(options);
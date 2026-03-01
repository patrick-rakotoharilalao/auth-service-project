import swaggerJsdoc from 'swagger-jsdoc';

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
                url: 'http://localhost:3001',
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
    apis: ['./src/routes/*.ts', './src/controllers/*.ts'],
};

export const swaggerSpec = swaggerJsdoc(options);
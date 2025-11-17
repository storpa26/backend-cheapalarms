<?php

namespace CheapAlarms\Plugin\Services;

use CheapAlarms\Plugin\Config\Config;
use WP_Error;

use function sanitize_email;
use function sanitize_text_field;
use function sanitize_textarea_field;

class ServiceM8Service
{
    public function __construct(
        private ServiceM8Client $client,
        private Config $config,
        private Logger $logger
    ) {
    }

    /**
     * Test ServiceM8 API connection
     *
     * @return array{ok: bool, hasKey: bool, message: string, testData?: array}
     */
    public function testConnection(): array
    {
        $apiKey = $this->config->getServiceM8ApiKey();
        
        if (empty($apiKey)) {
            return [
                'ok' => false,
                'hasKey' => false,
                'message' => 'SERVICEM8_API_KEY not configured',
            ];
        }

        try {
            $companies = $this->client->get('/company.json');
            
            if (is_wp_error($companies)) {
                return [
                    'ok' => false,
                    'hasKey' => true,
                    'message' => 'API key configured but connection failed',
                    'error' => $companies->get_error_message(),
                    'status' => $companies->get_error_data()['code'] ?? 500,
                ];
            }

            return [
                'ok' => true,
                'hasKey' => true,
                'message' => 'ServiceM8 API connection successful',
                'testData' => [
                    'companiesCount' => is_array($companies) ? count($companies) : 0,
                    'sample' => is_array($companies) && count($companies) > 0 ? $companies[0] : null,
                ],
            ];
        } catch (\Exception $e) {
            $this->logger->error('ServiceM8 test connection exception', [
                'error' => $e->getMessage(),
            ]);
            return [
                'ok' => false,
                'hasKey' => true,
                'message' => 'API key configured but connection failed',
                'error' => $e->getMessage(),
            ];
        }
    }

    /**
     * Get companies (clients)
     *
     * @param array<string, mixed> $params Query parameters (uuid, name)
     * @return array|WP_Error
     */
    public function getCompanies(array $params = [])
    {
        $query = [];
        if (!empty($params['uuid'])) {
            $query['uuid'] = sanitize_text_field($params['uuid']);
        }
        if (!empty($params['name'])) {
            $query['name'] = sanitize_text_field($params['name']);
        }

        $result = $this->client->get('/company.json', $query);
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'companies' => is_array($result) ? $result : [$result],
            'count' => is_array($result) ? count($result) : 1,
        ];
    }

    /**
     * Create a company (client)
     *
     * @param array<string, mixed> $data Company data
     * @return array|WP_Error
     */
    public function createCompany(array $data)
    {
        if (empty($data['name'])) {
            return new WP_Error('servicem8_validation', 'Company name is required', ['status' => 400]);
        }

        $companyData = [
            'name' => sanitize_text_field($data['name']),
        ];

        if (!empty($data['email'])) {
            $companyData['email'] = sanitize_email($data['email']);
        }
        if (!empty($data['phone'])) {
            $companyData['phone'] = sanitize_text_field($data['phone']);
        }
        if (!empty($data['address'])) {
            $companyData['address'] = sanitize_text_field($data['address']);
        }
        if (!empty($data['city'])) {
            $companyData['city'] = sanitize_text_field($data['city']);
        }
        if (!empty($data['state'])) {
            $companyData['state'] = sanitize_text_field($data['state']);
        }
        if (!empty($data['postcode'])) {
            $companyData['postcode'] = sanitize_text_field($data['postcode']);
        }
        if (!empty($data['country'])) {
            $companyData['country'] = sanitize_text_field($data['country']);
        }

        $result = $this->client->post('/company.json', $companyData);
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'company' => $result,
        ];
    }

    /**
     * Get jobs
     *
     * @param array<string, mixed> $params Query parameters (uuid, company_uuid, status)
     * @return array|WP_Error
     */
    public function getJobs(array $params = [])
    {
        $query = [];
        if (!empty($params['uuid'])) {
            $query['uuid'] = sanitize_text_field($params['uuid']);
        }
        if (!empty($params['company_uuid'])) {
            $query['company_uuid'] = sanitize_text_field($params['company_uuid']);
        }
        if (!empty($params['status'])) {
            $query['status'] = sanitize_text_field($params['status']);
        }

        $result = $this->client->get('/job.json', $query);
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'jobs' => is_array($result) ? $result : [$result],
            'count' => is_array($result) ? count($result) : 1,
        ];
    }

    /**
     * Get a single job by UUID
     *
     * @param string $uuid Job UUID
     * @return array|WP_Error
     */
    public function getJob(string $uuid)
    {
        if (empty($uuid)) {
            return new WP_Error('servicem8_validation', 'Job UUID is required', ['status' => 400]);
        }

        $result = $this->client->get('/job/' . sanitize_text_field($uuid) . '.json');
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'job' => $result,
        ];
    }

    /**
     * Create a job
     *
     * @param array<string, mixed> $data Job data
     * @return array|WP_Error
     */
    public function createJob(array $data)
    {
        if (empty($data['company_uuid'])) {
            return new WP_Error('servicem8_validation', 'company_uuid is required', ['status' => 400]);
        }

        $jobData = [
            'company_uuid' => sanitize_text_field($data['company_uuid']),
        ];
        
        // Job status is mandatory - default to 'Quote' if not provided
        // ServiceM8 requires 'status' field (not 'job_status')
        // Support both field names for flexibility
        $jobStatus = !empty($data['status']) 
            ? sanitize_text_field($data['status']) 
            : (!empty($data['job_status']) 
                ? sanitize_text_field($data['job_status']) 
                : 'Quote');
        $jobData['status'] = $jobStatus;

        if (!empty($data['job_type_uuid'])) {
            $jobData['job_type_uuid'] = sanitize_text_field($data['job_type_uuid']);
        }
        if (!empty($data['assigned_to_staff_uuid'])) {
            $jobData['assigned_to_staff_uuid'] = sanitize_text_field($data['assigned_to_staff_uuid']);
        }
        if (!empty($data['scheduled_start_date'])) {
            $jobData['scheduled_start_date'] = sanitize_text_field($data['scheduled_start_date']);
        }
        if (!empty($data['scheduled_end_date'])) {
            $jobData['scheduled_end_date'] = sanitize_text_field($data['scheduled_end_date']);
        }
        if (!empty($data['description'])) {
            $jobData['description'] = sanitize_textarea_field($data['description']);
        }
        if (!empty($data['address'])) {
            $jobData['address'] = sanitize_text_field($data['address']);
        }

        // Allow other fields to pass through
        foreach ($data as $key => $value) {
            if (!in_array($key, ['company_uuid', 'status', 'job_status', 'job_type_uuid', 'assigned_to_staff_uuid', 
                'scheduled_start_date', 'scheduled_end_date', 'description', 'address'])) {
                $jobData[$key] = $value;
            }
        }

        // Log the job data being sent for debugging
        $this->logger->info('ServiceM8 creating job', [
            'jobData' => $jobData,
            'hasStatus' => isset($jobData['status']),
            'statusValue' => $jobData['status'] ?? 'NOT SET',
        ]);
        
        $result = $this->client->post('/job.json', $jobData);
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'job' => $result,
        ];
    }

    /**
     * Delete a job
     *
     * @param string $uuid Job UUID
     * @return array|WP_Error
     */
    public function deleteJob(string $uuid)
    {
        if (empty($uuid)) {
            return new WP_Error('servicem8_validation', 'Job UUID is required', ['status' => 400]);
        }

        $result = $this->client->delete('/job/' . sanitize_text_field($uuid) . '.json');
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'message' => 'Job deleted successfully',
        ];
    }
}


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
        private Logger $logger,
        private ?EstimateService $estimateService = null
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
     * @param array<string, mixed> $params Query parameters (uuid, name, email)
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
        // Note: ServiceM8 API may not support email filter directly, so we'll filter in PHP if needed

        $result = $this->client->get('/company.json', $query);
        
        if (is_wp_error($result)) {
            return $result;
        }

        $companies = is_array($result) ? $result : [$result];

        // Filter by email if provided (ServiceM8 API doesn't support email filter)
        if (!empty($params['email'])) {
            $email = strtolower(sanitize_email($params['email']));
            $companies = array_filter($companies, function ($company) use ($email) {
                $companyEmail = strtolower($company['email'] ?? '');
                return $companyEmail === $email;
            });
            $companies = array_values($companies); // Re-index array
        }

        return [
            'ok' => true,
            'companies' => $companies,
            'count' => count($companies),
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
     * Get staff/workers
     *
     * @param array<string, mixed> $params Query parameters (uuid, name, email)
     * @return array|WP_Error
     */
    public function getStaff(array $params = [])
    {
        $query = [];
        if (!empty($params['uuid'])) {
            $query['uuid'] = sanitize_text_field($params['uuid']);
        }
        if (!empty($params['name'])) {
            $query['name'] = sanitize_text_field($params['name']);
        }
        if (!empty($params['email'])) {
            $query['email'] = sanitize_email($params['email']);
        }

        $result = $this->client->get('/staff.json', $query);
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'staff' => is_array($result) ? $result : [$result],
            'count' => is_array($result) ? count($result) : 1,
        ];
    }

    /**
     * Get a single staff member by UUID
     *
     * @param string $uuid Staff UUID
     * @return array|WP_Error
     */
    public function getStaffMember(string $uuid)
    {
        if (empty($uuid)) {
            return new WP_Error('servicem8_validation', 'Staff UUID is required', ['status' => 400]);
        }

        $result = $this->client->get('/staff/' . sanitize_text_field($uuid) . '.json');
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'staff' => $result,
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
        // ServiceM8 uses 'notes' not 'description'
        if (!empty($data['notes'])) {
            $jobData['notes'] = sanitize_textarea_field($data['notes']);
        } elseif (!empty($data['description'])) {
            // Support 'description' as alias for 'notes' for backward compatibility
            $jobData['notes'] = sanitize_textarea_field($data['description']);
        }
        if (!empty($data['address'])) {
            $jobData['address'] = sanitize_text_field($data['address']);
        }

        // Allow other fields to pass through
        foreach ($data as $key => $value) {
            if (!in_array($key, ['company_uuid', 'status', 'job_status', 'job_type_uuid', 'assigned_to_staff_uuid', 
                'scheduled_start_date', 'scheduled_end_date', 'description', 'notes', 'address'])) {
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
     * Update a job
     *
     * @param string $uuid Job UUID
     * @param array<string, mixed> $data Job data to update
     * @return array|WP_Error
     */
    public function updateJob(string $uuid, array $data)
    {
        if (empty($uuid)) {
            return new WP_Error('servicem8_validation', 'Job UUID is required', ['status' => 400]);
        }

        $jobData = [];

        // Map common fields
        if (isset($data['status'])) {
            $jobData['status'] = sanitize_text_field($data['status']);
        }
        // ServiceM8 uses 'job_description' not 'notes'
        if (isset($data['job_description'])) {
            $jobData['job_description'] = sanitize_textarea_field($data['job_description']);
        } elseif (isset($data['notes'])) {
            // Support 'notes' as alias for 'job_description'
            $jobData['job_description'] = sanitize_textarea_field($data['notes']);
        } elseif (isset($data['description'])) {
            // Support 'description' as alias for 'job_description'
            $jobData['job_description'] = sanitize_textarea_field($data['description']);
        }
        if (isset($data['address']) || isset($data['job_address'])) {
            $jobData['job_address'] = sanitize_text_field($data['job_address'] ?? $data['address']);
        }
        if (isset($data['assigned_to_staff_uuid'])) {
            $jobData['assigned_to_staff_uuid'] = sanitize_text_field($data['assigned_to_staff_uuid']);
        }
        if (isset($data['scheduled_start_date'])) {
            $jobData['scheduled_start_date'] = sanitize_text_field($data['scheduled_start_date']);
        }
        if (isset($data['scheduled_end_date'])) {
            $jobData['scheduled_end_date'] = sanitize_text_field($data['scheduled_end_date']);
        }
        if (isset($data['job_type_uuid'])) {
            $jobData['job_type_uuid'] = sanitize_text_field($data['job_type_uuid']);
        }

        // Allow other fields to pass through
        foreach ($data as $key => $value) {
            if (!in_array($key, ['status', 'notes', 'description', 'job_description', 'address', 'job_address', 
                'assigned_to_staff_uuid', 'scheduled_start_date', 'scheduled_end_date', 'job_type_uuid'])) {
                $jobData[$key] = $value;
            }
        }

        // ServiceM8 API docs say POST for update, but PUT should also work
        $result = $this->client->put('/job/' . sanitize_text_field($uuid) . '.json', $jobData);
        
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

    /**
     * Ensure a ServiceM8 company exists (create if missing)
     * Public method for MVP - ensures company exists before creating job
     *
     * @param array<string, mixed> $contact Contact data (name, email, phone, address, etc.)
     * @return array{ok: bool, company: array, created: bool}|WP_Error
     */
    public function ensureCompany(array $contact): array|WP_Error
    {
        return $this->findOrCreateCompany($contact);
    }

    /**
     * Find or create a ServiceM8 company from estimate contact
     *
     * @param array<string, mixed> $contact Estimate contact data
     * @return array{ok: bool, company: array, created: bool}|WP_Error
     */
    private function findOrCreateCompany(array $contact): array|WP_Error
    {
        $email = sanitize_email($contact['email'] ?? '');
        // Fix: Properly handle null values in concatenation to avoid trailing spaces
        $name = sanitize_text_field(
            $contact['name'] 
            ?? trim(($contact['firstName'] ?? '') . ' ' . ($contact['lastName'] ?? '')) 
            ?: ''
        );
        $phone = sanitize_text_field($contact['phone'] ?? $contact['phoneNo'] ?? '');

        if (empty($name)) {
            return new WP_Error('servicem8_validation', 'Company name is required (from estimate contact)', ['status' => 400]);
        }

        // Try to find existing company by email first
        if (!empty($email)) {
            $companies = $this->getCompanies(['email' => $email]);
            if (!is_wp_error($companies) && !empty($companies['companies'])) {
                $company = is_array($companies['companies']) ? $companies['companies'][0] : $companies['companies'];
                $this->logger->info('Found existing ServiceM8 company by email', [
                    'email' => $email,
                    'company_uuid' => $company['uuid'] ?? null,
                ]);
                return [
                    'ok' => true,
                    'company' => $company,
                    'created' => false,
                ];
            }
        }

        // Try to find by name
        if (!empty($name)) {
            $companies = $this->getCompanies(['name' => $name]);
            if (!is_wp_error($companies) && !empty($companies['companies'])) {
                $company = is_array($companies['companies']) ? $companies['companies'][0] : $companies['companies'];
                $this->logger->info('Found existing ServiceM8 company by name', [
                    'name' => $name,
                    'company_uuid' => $company['uuid'] ?? null,
                ]);
                return [
                    'ok' => true,
                    'company' => $company,
                    'created' => false,
                ];
            }
        }

        // Create new company
        $companyData = [
            'name' => $name,
        ];
        if (!empty($email)) {
            $companyData['email'] = $email;
        }
        if (!empty($phone)) {
            $companyData['phone'] = $phone;
        }

        // Extract address from contact if available
        if (!empty($contact['address'])) {
            $companyData['address'] = sanitize_text_field($contact['address']);
        }
        if (!empty($contact['city'])) {
            $companyData['city'] = sanitize_text_field($contact['city']);
        }
        if (!empty($contact['state'])) {
            $companyData['state'] = sanitize_text_field($contact['state']);
        }
        if (!empty($contact['postcode']) || !empty($contact['zip'])) {
            $companyData['postcode'] = sanitize_text_field($contact['postcode'] ?? $contact['zip'] ?? '');
        }
        if (!empty($contact['country'])) {
            $companyData['country'] = sanitize_text_field($contact['country']);
        }

        $result = $this->createCompany($companyData);
        if (is_wp_error($result)) {
            return $result;
        }

        $this->logger->info('Created new ServiceM8 company from estimate', [
            'name' => $name,
            'email' => $email,
            'company_uuid' => $result['company']['uuid'] ?? null,
        ]);

        return [
            'ok' => true,
            'company' => $result['company'],
            'created' => true,
        ];
    }

    /**
     * Create a ServiceM8 job from a GHL estimate
     * Includes idempotency check - will not create duplicate job if estimate already has job_uuid
     *
     * @param string $estimateId GHL estimate ID
     * @param string $locationId GHL location ID
     * @param array<string, mixed> $options Optional: status, assigned_to_staff_uuid, scheduled_start_date, etc.
     * @param JobLinkService|null $linkService Optional: JobLinkService for idempotency check
     * @return array{ok: bool, job: array, company: array, companyCreated: bool, jobUuid: string}|WP_Error
     */
    public function createJobFromEstimate(string $estimateId, string $locationId, array $options = [], ?JobLinkService $linkService = null): array|WP_Error
    {
        if (empty($estimateId)) {
            return new WP_Error('servicem8_validation', 'Estimate ID is required', ['status' => 400]);
        }

        if (!$this->estimateService) {
            return new WP_Error('servicem8_config', 'EstimateService not available', ['status' => 500]);
        }

        // IDEMPOTENCY CHECK: If estimate already has servicem8.job_uuid, do NOT create a new job
        if ($linkService) {
            $existingJobUuid = $linkService->getJobUuidByEstimateId($estimateId);
            if ($existingJobUuid) {
                $this->logger->info('Job already exists for estimate - returning existing job', [
                    'estimateId' => $estimateId,
                    'existingJobUuid' => $existingJobUuid,
                ]);
                
                // Return existing job data
                $existingJob = $this->getJob($existingJobUuid);
                if (!is_wp_error($existingJob)) {
                    // Get company info
                    $jobData = $existingJob['job'] ?? [];
                    $companyUuid = $jobData['company_uuid'] ?? null;
                    $company = null;
                    if ($companyUuid) {
                        $companyResult = $this->getCompanies(['uuid' => $companyUuid]);
                        if (!is_wp_error($companyResult) && !empty($companyResult['companies'])) {
                            $company = is_array($companyResult['companies']) ? $companyResult['companies'][0] : $companyResult['companies'];
                        }
                    }
                    
                    return [
                        'ok' => true,
                        'job' => $jobData,
                        'jobUuid' => $existingJobUuid,
                        'company' => $company,
                        'companyCreated' => false,
                        'alreadyExists' => true,
                    ];
                }
            }
        }

        // Fetch estimate data
        $estimate = $this->estimateService->getEstimate([
            'estimateId' => $estimateId,
            'locationId' => $locationId,
        ]);

        if (is_wp_error($estimate)) {
            return $estimate;
        }

        if (empty($estimate)) {
            return new WP_Error('servicem8_not_found', 'Estimate not found', ['status' => 404]);
        }

        // Extract contact information
        $contact = $estimate['contact'] ?? $estimate['contactDetails'] ?? [];
        if (empty($contact)) {
            return new WP_Error('servicem8_validation', 'Estimate contact information is missing', ['status' => 400]);
        }

        // Find or create company
        $companyResult = $this->findOrCreateCompany($contact);
        if (is_wp_error($companyResult)) {
            return $companyResult;
        }

        $company = $companyResult['company'];
        $companyUuid = $company['uuid'] ?? null;
        if (empty($companyUuid)) {
            return new WP_Error('servicem8_error', 'Company UUID not found in ServiceM8 response', ['status' => 500]);
        }

        // Build job description from estimate items
        $description = '';
        if (!empty($estimate['items']) && is_array($estimate['items'])) {
            $itemDescriptions = [];
            foreach ($estimate['items'] as $item) {
                $itemName = $item['name'] ?? '';
                $itemQty = $item['qty'] ?? $item['quantity'] ?? 1;
                $itemDesc = $item['description'] ?? '';
                if ($itemName) {
                    $line = $itemQty > 1 ? "{$itemQty}x {$itemName}" : $itemName;
                    if ($itemDesc) {
                        $line .= " - {$itemDesc}";
                    }
                    $itemDescriptions[] = $line;
                }
            }
            $description = implode("\n", $itemDescriptions);
        }

        // Add estimate number to description if available
        $estimateNumber = $estimate['estimateNumber'] ?? $estimateId;
        if ($description) {
            $description = "Estimate #{$estimateNumber}\n\n{$description}";
        } else {
            $description = "Estimate #{$estimateNumber}";
        }

        // Build job data for creation (minimal fields - some fields may not be accepted during creation)
        $createJobData = [
            'company_uuid' => $companyUuid,
            'status' => $options['status'] ?? 'Quote',
        ];

        // Create the job with minimal data first
        $result = $this->createJob($createJobData);
        if (is_wp_error($result)) {
            return $result;
        }

        // Extract job UUID from response
        $jobResponse = $result['job'] ?? $result;
        $jobUuid = $jobResponse['uuid'] ?? $jobResponse['job_uuid'] ?? $jobResponse['id'] ?? null;

        if (empty($jobUuid)) {
            // Try to fetch UUID from company's jobs if not in response
            $jobsResult = $this->getJobs(['company_uuid' => $companyUuid]);
            if (!is_wp_error($jobsResult) && !empty($jobsResult['jobs'])) {
                $jobs = is_array($jobsResult['jobs']) ? $jobsResult['jobs'] : [$jobsResult['jobs']];
                if (!empty($jobs)) {
                    $mostRecent = $jobs[0];
                    $jobUuid = $mostRecent['uuid'] ?? null;
                    $jobResponse = $mostRecent;
                }
            }
        }

        if (empty($jobUuid)) {
            $this->logger->error('Cannot update job: UUID not found after creation', [
                'estimateId' => $estimateId,
                'response' => $jobResponse,
            ]);
            // Return what we have even without UUID
            return [
                'ok' => true,
                'job' => $jobResponse,
                'company' => $company,
                'companyCreated' => $companyResult['created'],
                'warning' => 'Job created but UUID not found - cannot update with details',
            ];
        }

        // Now update the job with all the details (job_description, address, etc.)
        $updateJobData = [
            'job_description' => $description, // ServiceM8 uses 'job_description' not 'notes'
        ];

        // Add address - ServiceM8 uses 'job_address' for update
        if (!empty($contact['address'])) {
            $updateJobData['job_address'] = sanitize_text_field($contact['address']);
        } elseif (!empty($estimate['address'])) {
            $updateJobData['job_address'] = sanitize_text_field($estimate['address']);
        }

        // Add optional fields from options
        if (!empty($options['assigned_to_staff_uuid'])) {
            $updateJobData['assigned_to_staff_uuid'] = sanitize_text_field($options['assigned_to_staff_uuid']);
        }
        if (!empty($options['scheduled_start_date'])) {
            $updateJobData['scheduled_start_date'] = sanitize_text_field($options['scheduled_start_date']);
        }
        if (!empty($options['scheduled_end_date'])) {
            $updateJobData['scheduled_end_date'] = sanitize_text_field($options['scheduled_end_date']);
        }
        if (!empty($options['job_type_uuid'])) {
            $updateJobData['job_type_uuid'] = sanitize_text_field($options['job_type_uuid']);
        }

        // Update the job with all details
        $updateResult = $this->updateJob($jobUuid, $updateJobData);
        if (is_wp_error($updateResult)) {
            $this->logger->warning('Failed to update job with details, but job was created', [
                'estimateId' => $estimateId,
                'jobUuid' => $jobUuid,
                'error' => $updateResult->get_error_message(),
            ]);
            // Continue anyway - job was created successfully
        } else {
            // Use updated job data
            $jobResponse = $updateResult['job'] ?? $jobResponse;
        }

        $this->logger->info('Created ServiceM8 job from estimate', [
            'estimateId' => $estimateId,
            'jobUuid' => $jobUuid,
            'companyUuid' => $companyUuid,
            'companyCreated' => $companyResult['created'],
            'responseStructure' => array_keys($jobResponse ?? []),
        ]);

        return [
            'ok' => true,
            'job' => $jobResponse,
            'jobUuid' => $jobUuid, // Explicitly include UUID for easier access
            'company' => $company,
            'companyCreated' => $companyResult['created'],
        ];
    }

    /**
     * Update an existing ServiceM8 job from a GHL estimate
     *
     * @param string $estimateId GHL estimate ID
     * @param string $locationId GHL location ID
     * @param string $jobUuid ServiceM8 job UUID to update
     * @param array<string, mixed> $options Optional: status, assigned_to_staff_uuid, scheduled_start_date, etc.
     * @return array{ok: bool, job: array, company: array}|WP_Error
     */
    public function updateJobFromEstimate(string $estimateId, string $locationId, string $jobUuid, array $options = []): array|WP_Error
    {
        if (empty($estimateId)) {
            return new WP_Error('servicem8_validation', 'Estimate ID is required', ['status' => 400]);
        }

        if (empty($jobUuid)) {
            return new WP_Error('servicem8_validation', 'Job UUID is required', ['status' => 400]);
        }

        if (!$this->estimateService) {
            return new WP_Error('servicem8_config', 'EstimateService not available', ['status' => 500]);
        }

        // Fetch estimate data
        $estimate = $this->estimateService->getEstimate([
            'estimateId' => $estimateId,
            'locationId' => $locationId,
        ]);

        if (is_wp_error($estimate)) {
            return $estimate;
        }

        if (empty($estimate)) {
            return new WP_Error('servicem8_not_found', 'Estimate not found', ['status' => 404]);
        }

        // Extract contact information
        $contact = $estimate['contact'] ?? $estimate['contactDetails'] ?? [];

        // Build job description from estimate items
        $description = '';
        if (!empty($estimate['items']) && is_array($estimate['items'])) {
            $itemDescriptions = [];
            foreach ($estimate['items'] as $item) {
                $itemName = $item['name'] ?? '';
                $itemQty = $item['qty'] ?? $item['quantity'] ?? 1;
                $itemDesc = $item['description'] ?? '';
                if ($itemName) {
                    $line = $itemQty > 1 ? "{$itemQty}x {$itemName}" : $itemName;
                    if ($itemDesc) {
                        $line .= " - {$itemDesc}";
                    }
                    $itemDescriptions[] = $line;
                }
            }
            $description = implode("\n", $itemDescriptions);
        }

        // Add estimate number to description if available
        $estimateNumber = $estimate['estimateNumber'] ?? $estimateId;
        if ($description) {
            $description = "Estimate #{$estimateNumber}\n\n{$description}";
        } else {
            $description = "Estimate #{$estimateNumber}";
        }

        // Build update data
        $updateJobData = [
            'job_description' => $description, // ServiceM8 uses 'job_description' not 'notes'
        ];

        // Add address - ServiceM8 uses 'job_address' for update
        if (!empty($contact['address'])) {
            $updateJobData['job_address'] = sanitize_text_field($contact['address']);
        } elseif (!empty($estimate['address'])) {
            $updateJobData['job_address'] = sanitize_text_field($estimate['address']);
        }

        // Add optional fields from options (only if provided)
        if (isset($options['status'])) {
            $updateJobData['status'] = sanitize_text_field($options['status']);
        }
        if (isset($options['assigned_to_staff_uuid'])) {
            $updateJobData['assigned_to_staff_uuid'] = sanitize_text_field($options['assigned_to_staff_uuid']);
        }
        if (isset($options['scheduled_start_date'])) {
            $updateJobData['scheduled_start_date'] = sanitize_text_field($options['scheduled_start_date']);
        }
        if (isset($options['scheduled_end_date'])) {
            $updateJobData['scheduled_end_date'] = sanitize_text_field($options['scheduled_end_date']);
        }
        if (isset($options['job_type_uuid'])) {
            $updateJobData['job_type_uuid'] = sanitize_text_field($options['job_type_uuid']);
        }

        // Update the job
        $result = $this->updateJob($jobUuid, $updateJobData);
        if (is_wp_error($result)) {
            return $result;
        }

        // Get company info from the job (we already have it from the link, but fetch for consistency)
        $jobResponse = $result['job'] ?? [];
        $companyUuid = $jobResponse['company_uuid'] ?? null;
        $company = null;
        
        if ($companyUuid) {
            $companyResult = $this->getCompanies(['uuid' => $companyUuid]);
            if (!is_wp_error($companyResult) && !empty($companyResult['companies'])) {
                $company = is_array($companyResult['companies']) ? $companyResult['companies'][0] : $companyResult['companies'];
            }
        }

        $this->logger->info('Updated ServiceM8 job from estimate', [
            'estimateId' => $estimateId,
            'jobUuid' => $jobUuid,
            'companyUuid' => $companyUuid,
        ]);

        return [
            'ok' => true,
            'job' => $jobResponse,
            'jobUuid' => $jobUuid,
            'company' => $company,
        ];
    }

    /**
     * Get job activities for a job (scheduling information)
     *
     * @param string $jobUuid ServiceM8 job UUID
     * @return array{ok: bool, activities: array, count: int}|WP_Error
     */
    public function getJobActivities(string $jobUuid)
    {
        if (empty($jobUuid)) {
            return new WP_Error('servicem8_validation', 'Job UUID is required', ['status' => 400]);
        }

        $result = $this->client->get('/jobactivity.json', ['job_uuid' => sanitize_text_field($jobUuid)]);
        
        if (is_wp_error($result)) {
            return $result;
        }

        return [
            'ok' => true,
            'activities' => is_array($result) ? $result : [$result],
            'count' => is_array($result) ? count($result) : 1,
        ];
    }

    /**
     * Schedule a job by creating a Job Activity
     * This is the correct way to schedule in ServiceM8 (not just updating job fields)
     *
     * @param string $jobUuid ServiceM8 job UUID
     * @param string $staffUuid Staff/technician UUID to assign
     * @param string $startDate Scheduled start date/time (ISO8601 format: "2024-12-15 09:00:00")
     * @param string $endDate Scheduled end date/time (ISO8601 format: "2024-12-15 12:00:00")
     * @param JobLinkService|null $linkService Optional: For idempotency check (prevent duplicate activities)
     * @return array{ok: bool, activity: array}|WP_Error
     */
    public function scheduleJob(string $jobUuid, string $staffUuid, string $startDate, string $endDate, ?JobLinkService $linkService = null): array|WP_Error
    {
        if (empty($jobUuid)) {
            return new WP_Error('servicem8_validation', 'Job UUID is required', ['status' => 400]);
        }
        if (empty($staffUuid)) {
            return new WP_Error('servicem8_validation', 'Staff UUID is required', ['status' => 400]);
        }
        if (empty($startDate) || empty($endDate)) {
            return new WP_Error('servicem8_validation', 'Start date and end date are required', ['status' => 400]);
        }

        // IDEMPOTENCY CHECK: If scheduling already exists for that job (matching time window), do NOT create duplicate activity
        if ($linkService) {
            $existingActivities = $this->getJobActivities($jobUuid);
            if (!is_wp_error($existingActivities)) {
                $activities = $existingActivities['activities'] ?? [];
                foreach ($activities as $activity) {
                    $activityStart = $activity['start_date'] ?? $activity['scheduled_start_date'] ?? null;
                    $activityEnd = $activity['end_date'] ?? $activity['scheduled_end_date'] ?? null;
                    $activityStaff = $activity['staff_uuid'] ?? $activity['assigned_to_staff_uuid'] ?? null;
                    
                    // Check if activity matches (same time window and staff)
                    if ($activityStart === $startDate && $activityEnd === $endDate && $activityStaff === $staffUuid) {
                        $this->logger->info('Job activity already exists for this time window - returning existing', [
                            'jobUuid' => $jobUuid,
                            'startDate' => $startDate,
                            'endDate' => $endDate,
                            'staffUuid' => $staffUuid,
                        ]);
                        
                        return [
                            'ok' => true,
                            'activity' => $activity,
                            'alreadyExists' => true,
                        ];
                    }
                }
            }
        }

        // Create Job Activity (this is the correct way to schedule in ServiceM8)
        $activityData = [
            'job_uuid' => sanitize_text_field($jobUuid),
            'staff_uuid' => sanitize_text_field($staffUuid),
            'start_date' => sanitize_text_field($startDate),
            'end_date' => sanitize_text_field($endDate),
        ];

        $this->logger->info('Creating ServiceM8 job activity for scheduling', [
            'jobUuid' => $jobUuid,
            'staffUuid' => $staffUuid,
            'startDate' => $startDate,
            'endDate' => $endDate,
        ]);

        $result = $this->client->post('/jobactivity.json', $activityData);
        
        if (is_wp_error($result)) {
            return $result;
        }

        $this->logger->info('ServiceM8 job activity created successfully', [
            'jobUuid' => $jobUuid,
            'activityUuid' => $result['uuid'] ?? null,
        ]);

        return [
            'ok' => true,
            'activity' => $result,
        ];
    }
}


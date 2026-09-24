-- Dry run for DID migration
SELECT 'users' as table_name, 'did' as column_name, count(*) as affected_count, 
       array_agg(distinct did) as unique_values
FROM users 
WHERE did LIKE 'did:ethr:31337:%';

SELECT 'assets' as table_name, 'owner_did' as column_name, count(*) as affected_count, 
       array_agg(distinct owner_did) as unique_values
FROM assets 
WHERE owner_did LIKE 'did:ethr:31337:%';

SELECT 'assets' as table_name, 'custodian_did' as column_name, count(*) as affected_count, 
       array_agg(distinct custodian_did) as unique_values
FROM assets 
WHERE custodian_did LIKE 'did:ethr:31337:%';

SELECT 'verifiable_credentials' as table_name, 'subject_did' as column_name, count(*) as affected_count, 
       array_agg(distinct subject_did) as unique_values
FROM verifiable_credentials 
WHERE subject_did LIKE 'did:ethr:31337:%';

SELECT 'verifiable_credentials' as table_name, 'issuer_did' as column_name, count(*) as affected_count, 
       array_agg(distinct issuer_did) as unique_values
FROM verifiable_credentials 
WHERE issuer_did LIKE 'did:ethr:31337:%';

SELECT 'audit_events' as table_name, 'actor_did' as column_name, count(*) as affected_count, 
       array_agg(distinct actor_did) as unique_values
FROM audit_events 
WHERE actor_did LIKE 'did:ethr:31337:%';

SELECT 'audit_events' as table_name, 'target_did' as column_name, count(*) as affected_count, 
       array_agg(distinct target_did) as unique_values
FROM audit_events 
WHERE target_did LIKE 'did:ethr:31337:%';

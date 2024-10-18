The Google Workspace Target Connector makes it possible to connect Google Workspace – previously Google G Suite – via the Identity & Access Management (IAM) solution HelloID by Tools4ever to a range of source systems. With this integration you can improve the management of access rights and user accounts. The connector automates these processes in Google Workspace, based on the data in the source system. Not only does it save you time, it also makes sure the changes get executed without errors.  In this article, you will read more about this connector and the possibilities.

## What is Google Workspace?

Google Workspace is a comprehensive software package that supports your business. For many companies, it provides all the software they need at once, making the suite particularly appealing. Google Workspace is cloud-based, which means you don’t have to install any software locally. The software suite supports new ways of collaborating with others, which can take productivity to the next level.

## Why is a Google Workspace connector useful?

Employees need access to the right systems and data to be maximally productive. This requires the right user accounts and authorisations. Account management is an important component of the Identity life cycle (Creation, maintenance, termination) and requires a broad range of additional tasks. At the same time, compliance is a key focus point. You want to ensure and be able to demonstrate that authorisations are granted and revoked at the right moment. Connecting Google Workspace to your source systems via HelloID helps you to achieve this and will save you time.

You can connect Google Workspace via the Google Workspace connector to for example:
*	AFAS
*	Somtoday/Magister

Further details on linking to these source systems can be found later in the article.

## HelloID for Google Workspace helps you with

**Uniform account management:** The Google Workspace Target Connector offers you the certainty of uniform account management. The connector ensures that your accounts are managed consistently and prevents errors. This ensures that users always have a Google Workspace account at the right time so that they can be optimally productive.

**Alignment with the Identity Life Cycle process of your organization:** Your organization is evolving continuously. New employees join, people change roles and staff leaves the organization. The Google Workspace Target Connector ensures user account management is always aligned with the identity lifecycle process within your organization.

**Improved efficiency:** By connecting your source systems and Google Workspace, you can create Google Workspace accounts quicker and manage these accounts more efficiently. The integration automates account provision to a large extent. The moment a new account is added in your source system, HelloID detects this change and will automatically create a Google Workspace account. This allows employees to start to work faster and be productive sooner.

**Improved compliance:** By connecting your source systems to Google Workspace via HelloID, you always have a full audit trail available. The IAM solution logs all actions and mutations in detail. This way, you are always in full control and it enables you to demonstrate compliance with laws and regulations.

## How HelloID integrates with Google Workspace

The Google Workspace connector uses the Google Admin API, more specifically the directory/V1 endpoints for users, groups and customers. The Google Workspace connector user personal data from HelloID and creates a user account based on this information. Only the resulting account is sent to the Google API.

| Change in source system	| Procedure in Google Workspace |
| ----------------------  | ------------------------------ | 
| New employee |	When a new employee joins the company, this user needs to be able to get started as soon as possible. This requires the right accounts and authorisations. Thanks to the integration between your source systems and Google Workspace, HelloID can automatically create a user account in Google Workspace, without requiring any intervention. HelloID also grants the required authorisations immediately.|
| Employee changes role |	What if an employee changes role? This will also impact the authorisations the user needs. Thanks to the connector, HelloID immediately processes the job change and adapts the authorisations for Google Workspace.|
| Staff leaves the company |	When an employee leaves the company, HelloID deactivates their user account automatically in Google Workspace and informs the affected parties accordingly. After some time, HelloID automatically deletes the former employee's Google Workspace account.|

The connector supports dynamic permissions. Important to note here is that dynamic permissions in HelloID always work entirely on the basis of source data. For example, you can configure all departmental groups using one business rule. To enable this, HelloID looks for correlations between the source data and corresponding groups. 

Unlike non-dynamic permissions, dynamic permissions always move with changes in the structure of your organisation. For example, are you setting up a new department? Then HelloID recognises this change in your source system, creates the appropriate groups if necessary and then assigns accounts to the appropriate groups during the identity lifecycle process. A full audit trail of this process is available in HelloID.

## Customised data exchange

A key advantage of HelloID is that you are always at the helm and stay in full control. The integration of your source systems and Google Workspace is no exception. You therefore always determine in detail which data you exchange, and how this happens. The configuration of the Google Workspace connector determines exactly how an account is constructed. You can completely adjust the way of updating to the connector's update routine. 

Tools4ever of course supports you in setting up the connector. This is always accompanied by an intake and design session. In an intake document, we determine exactly how an account should be created. We also determine naming conventions, specifying how you want to construct a username and what HelloID should do if this username is not available. 

## Linking Google Workspace with source systems via HelloID
HelloID enables the integration of various source systems with Google Workspace. The connectors take your user and authorisation management to the next level. Some common integrations are:

* **AFAS - Google Workspace connector:** This connector keeps AFAS and Google Workspace fully in sync. You can copy important attributes from AFAS such as staff name, job title and department into Google Workspace. This streamlines the management of accounts and authorisations for employees.

* **Somtoday/Magister - Google Workspace connector:** Schools often use Somtoday or Magister. Using the Google Workspace Target Connector, you can easily link these electronic learning environments to Google Workspace. This will ensure that students have the right accounts and authorisations at the right time to optimise their learning.  

HelloID supports more than 200 connectors, which enables a broad range of integration possibilities between Google Workspace and other source and target systems. We are continuously expanding our offer of connectors and integrations, allowing you to integrate with all popular systems.


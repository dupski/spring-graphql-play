package org.revcrm

import graphql.GraphQL
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import graphql.schema.GraphQLSchema
import graphql.Scalars.GraphQLString
import graphql.schema.GraphQLFieldDefinition
import graphql.schema.GraphQLObjectType

@SpringBootApplication
class CRMApplication {

	@Bean
	fun getGraphQLSchema(): GraphQL {
		val queryType = GraphQLObjectType.newObject()
				.name("helloWorldQuery")
				.field(GraphQLFieldDefinition.newFieldDefinition()
						.type(GraphQLString)
						.name("hello")
						.staticValue("world"))
				.build()
		val schema = GraphQLSchema.newSchema()
				.query(queryType)
				.build()
		return GraphQL.newGraphQL(schema).build()
	}
}

fun main(args: Array<String>) {
	runApplication<CRMApplication>(*args)
}
